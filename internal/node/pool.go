package node

import (
	"encoding/json"
	"errors"
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
// <data>/pending.json so a restart does not lose them.
type Pool struct {
	mu    sync.Mutex
	path  string
	max   int
	items []poolItem
	ids   map[chain.Hash]bool
}

var errPoolFull = errors.New("pending pool is full")

func newPool(dir string, max int) (*Pool, error) {
	p := &Pool{path: filepath.Join(dir, "pending.json"), max: max, ids: map[chain.Hash]bool{}}
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &p.items); err != nil {
		return nil, err
	}
	for _, it := range p.items {
		p.ids[it.Entry.ID()] = true
	}
	return p, nil
}

func (p *Pool) save() {
	raw, _ := json.Marshal(p.items)
	tmp := p.path + ".tmp"
	if os.WriteFile(tmp, raw, 0o644) == nil {
		os.Rename(tmp, p.path)
	}
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
	p.items = append(p.items, it)
	p.ids[id] = true
	p.save()
	return true, nil
}

// Remove drops payloads by ID (those that made it into a block).
func (p *Pool) Remove(ids map[chain.Hash]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.items[:0]
	for _, it := range p.items {
		if id := it.Entry.ID(); ids[id] {
			delete(p.ids, id)
		} else {
			kept = append(kept, it)
		}
	}
	p.items = kept
	p.save()
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
	// Validate the shape of the change with no approvals required yet.
	probe := r
	probe.Signatures = nil
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
