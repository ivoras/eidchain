package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"eidchain/internal/chain"
)

// poolItem is a validated payload waiting for the next block.
type poolItem struct {
	Entry   chain.PayloadEntry `json:"entry"`
	Subject string             `json:"subject"`
	Serial  string             `json:"serial"`
	Added   int64              `json:"added"`
}

// Pool holds validated payloads that are not yet in a block. It is persisted to
// <data>/pending.jsonl, one item per line, so a restart does not lose them. Adding
// appends a line, which costs the same however full the pool is; only removal
// rewrites the file. Damage loses the damaged lines, never the node's ability to
// start, because pending payloads are the one thing here that can be resubmitted.
type Pool struct {
	mu    sync.Mutex
	path  string
	max   int
	items []poolItem
	ids   map[chain.Hash]bool
}

var errPoolFull = errors.New("pending pool is full")

func newPool(dir string, max int) (*Pool, error) {
	p := &Pool{path: filepath.Join(dir, "pending.jsonl"), max: max, ids: map[chain.Hash]bool{}}
	if err := p.migrate(filepath.Join(dir, "pending.json")); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	for i, line := range bytes.Split(raw, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var it poolItem
		if err := json.Unmarshal(line, &it); err != nil {
			log.Printf("pending pool: skipping damaged line %d: %v", i+1, err)
			continue
		}
		if id := it.Entry.ID(); !p.ids[id] {
			p.ids[id] = true
			p.items = append(p.items, it)
		}
	}
	return p, nil
}

// migrate converts the old pending.json, a single JSON array.
func (p *Pool) migrate(old string) error {
	raw, err := os.ReadFile(old)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &p.items); err != nil {
		log.Printf("pending pool: discarding unreadable %s: %v", old, err)
		p.items = nil
	}
	if err := p.rewrite(); err != nil {
		return err
	}
	p.items = nil
	return os.Remove(old)
}

// rewrite replaces the file atomically with the current items.
func (p *Pool) rewrite() error {
	var buf bytes.Buffer
	for _, it := range p.items {
		line, err := json.Marshal(it)
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return chain.WriteFileAtomic(p.path, buf.Bytes(), 0o644)
}

func (p *Pool) appendItem(it poolItem) error {
	line, err := json.Marshal(it)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	// The leading newline ends any line a crash left half written.
	if _, err := f.Write(append(append([]byte{'\n'}, line...), '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (p *Pool) Has(id chain.Hash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ids[id]
}

// Add queues a payload; false means it was already queued.
func (p *Pool) Add(it poolItem) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	id := it.Entry.ID()
	if p.ids[id] {
		return false, nil
	}
	if len(p.items) >= p.max {
		return false, errPoolFull
	}
	if err := p.appendItem(it); err != nil {
		return false, fmt.Errorf("save pending payload: %w", err)
	}
	p.items = append(p.items, it)
	p.ids[id] = true
	return true, nil
}

// Remove drops payloads by ID (those that made it into a block).
func (p *Pool) Remove(ids map[chain.Hash]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	kept := p.items[:0]
	for _, it := range p.items {
		if id := it.Entry.ID(); ids[id] {
			delete(p.ids, id)
		} else {
			kept = append(kept, it)
		}
	}
	if len(kept) == len(p.items) {
		return
	}
	p.items = kept
	if err := p.rewrite(); err != nil {
		log.Printf("pending pool: %v", err) // on restart the stale items are dropped as already on chain
	}
}

func (p *Pool) Snapshot() []poolItem {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]poolItem(nil), p.items...)
}

func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.items)
}

// RotationPool collects key-rotation proposals and their approvals until a
// quorum is reached. It lives in memory: approvals can be re-submitted.
type RotationPool struct {
	mu    sync.Mutex
	items map[chain.Hash]*chain.Rotation // by KeyChange hash
}

func newRotationPool() *RotationPool {
	return &RotationPool{items: map[chain.Hash]*chain.Rotation{}}
}

// Add validates the proposal and each approval against the current state and
// merges them. changed is false if nothing new was learnt.
func (rp *RotationPool) Add(p *chain.Params, st *chain.State, r chain.Rotation) (status chain.Hash, approvals int, changed bool, err error) {
	c := r.Change
	status = c.Hash()
	// Proposals must carry at least one approval. A proposal nobody signed costs
	// nothing to make, so accepting one would let anyone fill this pool.
	if len(r.Signatures) == 0 {
		return status, 0, false, errors.New("a rotation needs at least one authority's approval")
	}
	if c.Type != "replace" || c.Chain != p.GenesisHash || c.Seq != st.Seq || !st.Has(c.Old) {
		return status, 0, false, errors.New("rotation does not apply to the current chain state (type, chain, seq or old key)")
	}
	pub, derr := chain.DecodePublicKey(c.NewKey)
	if derr != nil {
		return status, 0, false, derr
	}
	if id, _ := chain.KeyID(pub); st.Has(id) {
		return status, 0, false, errors.New("new key is already an authority")
	}
	h := c.Hash()
	rp.mu.Lock()
	defer rp.mu.Unlock()
	cur := rp.items[h]
	if cur == nil {
		cur = &chain.Rotation{Change: c}
	}
	before := len(cur.Signatures)
	for _, s := range r.Signatures {
		key, ok := st.Keys[s.Signer]
		if !ok {
			return status, len(cur.Signatures), false, errors.New("approval from a key that is not a currently valid authority")
		}
		if !chain.VerifyKeyChangeSig(key, c, s) {
			return status, len(cur.Signatures), false, errors.New("invalid approval signature")
		}
		cur.AddSignature(s)
	}
	rp.items[h] = cur
	return status, len(cur.Signatures), len(cur.Signatures) > before, nil
}

// Ready returns rotations with enough approvals that apply, in order, to st.
func (rp *RotationPool) Ready(p *chain.Params, st *chain.State) []chain.Rotation {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var all []chain.Rotation
	for _, r := range rp.items {
		if len(r.Signatures) >= p.Rules.RotationQuorum {
			all = append(all, r.Clone())
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Change.Seq != all[j].Change.Seq {
			return all[i].Change.Seq < all[j].Change.Seq
		}
		return all[i].Change.Hash().String() < all[j].Change.Hash().String()
	})
	var out []chain.Rotation
	working := st
	for _, r := range all {
		if len(out) >= p.Rules.MaxRotationsPerBlock || r.Change.Seq != working.Seq {
			continue
		}
		next, err := p.ApplyRotation(st, working, r)
		if err != nil {
			continue
		}
		out = append(out, r)
		working = next
	}
	return out
}

// Prune drops proposals that can no longer apply after the state changed.
func (rp *RotationPool) Prune(st *chain.State) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	for h, r := range rp.items {
		if r.Change.Seq != st.Seq || !st.Has(r.Change.Old) {
			delete(rp.items, h)
		}
	}
}

func (rp *RotationPool) List() []chain.Rotation {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	var out []chain.Rotation
	for _, r := range rp.items {
		out = append(out, r.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Change.Hash().String() < out[j].Change.Hash().String() })
	return out
}

// find returns the pooled rotation for a KeyChange hash.
func (rp *RotationPool) find(h chain.Hash) *chain.Rotation {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if r := rp.items[h]; r != nil {
		c := r.Clone()
		return &c
	}
	return nil
}
