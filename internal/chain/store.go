package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned by AddBlock that callers react to.
var (
	ErrUnknownParent = errors.New("unknown parent block")
	ErrKnown         = errors.New("block already known")
)

type entry struct {
	block  *Block // nil for the genesis
	hash   Hash
	parent Hash
	height uint64
	time   int64
	state  *State // authority set after this block
}

// AddResult describes what AddBlock changed.
type AddResult struct {
	Hash     Hash
	NewHead  bool     // the canonical chain changed
	Adopted  []*Block // blocks that joined the canonical chain, oldest first
	Orphaned []*Block // blocks that left it (a reorg), oldest first
}

// Store keeps every valid block it has seen (including side branches) under
// <dir>/blocks and tracks the canonical chain: the highest, ties broken by the
// lowest block hash.
type Store struct {
	Dir string
	P   *Params

	// OnChange, if set, is called (without locks held) after a block is added.
	OnChange func(AddResult)

	mu     sync.RWMutex
	blocks map[Hash]*entry
	canon  []Hash        // canon[h] is the canonical block hash at height h
	ids    map[Hash]Hash // payload ID -> canonical block containing it
	now    func() time.Time
}

// GenesisPath returns where the genesis file lives in a data directory.
func GenesisPath(dir string) string { return filepath.Join(dir, "genesis.json") }

// Open loads the chain in dir. If expected is non-zero the stored genesis must
// hash to it. Invalid or orphaned block files are skipped with a warning.
func Open(dir string, expected Hash) (*Store, error) {
	g, err := LoadGenesis(GenesisPath(dir))
	if err != nil {
		return nil, fmt.Errorf("no usable chain in %s: %w (create one with `eidchain genesis` or fetch one with `eidchain pull`)", dir, err)
	}
	p, err := NewParams(g)
	if err != nil {
		return nil, err
	}
	if !expected.IsZero() && expected != p.GenesisHash {
		return nil, fmt.Errorf("genesis in %s has hash %s, but %s is configured", dir, p.GenesisHash, expected)
	}
	s := &Store{Dir: dir, P: p, blocks: map[Hash]*entry{}, ids: map[Hash]Hash{}, now: time.Now}
	s.blocks[p.GenesisHash] = &entry{hash: p.GenesisHash, height: 0, time: g.Created, state: p.Initial}
	s.canon = []Hash{p.GenesisHash}

	paths, _ := filepath.Glob(filepath.Join(dir, "blocks", "*.json"))
	var loaded []*Block
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var b Block
		if err := StrictUnmarshal(raw, &b); err != nil {
			log.Printf("store: skipping %s: %v", filepath.Base(path), err)
			continue
		}
		if want := strings.TrimSuffix(filepath.Base(path), ".json"); want != b.Hash().String() {
			log.Printf("store: skipping %s: file name does not match block hash", filepath.Base(path))
			continue
		}
		loaded = append(loaded, &b)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].Header.Height < loaded[j].Header.Height })
	for _, b := range loaded {
		if _, err := s.add(b, false); err != nil {
			log.Printf("store: skipping block %s: %v", b.Hash().Short(), err)
		}
	}
	return s, nil
}

// Init writes a new genesis into dir and opens it. It refuses to replace a
// different existing genesis.
func Init(dir string, g *Genesis) (*Store, error) {
	if existing, err := LoadGenesis(GenesisPath(dir)); err == nil && existing.Hash() != g.Hash() {
		return nil, fmt.Errorf("%s already holds a different chain (%s)", dir, existing.Hash())
	}
	if err := SaveGenesis(GenesisPath(dir), g); err != nil {
		return nil, err
	}
	return Open(dir, g.Hash())
}

func (s *Store) blockPath(h Hash) string { return filepath.Join(s.Dir, "blocks", h.String()+".json") }

// AddBlock validates b against its parent and stores it.
func (s *Store) AddBlock(b *Block) (AddResult, error) {
	res, err := s.add(b, true)
	if err == nil && s.OnChange != nil {
		s.OnChange(res)
	}
	return res, err
}

func (s *Store) add(b *Block, persist bool) (AddResult, error) {
	h := b.Hash()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blocks[h]; ok {
		return AddResult{Hash: h}, ErrKnown
	}
	par, ok := s.blocks[b.Header.Prev]
	if !ok {
		return AddResult{Hash: h}, ErrUnknownParent
	}
	state, err := s.P.ValidateBlock(b, s.parentInfoLocked(par), s.now())
	if err != nil {
		return AddResult{Hash: h}, err
	}
	if persist {
		raw, _ := json.Marshal(b)
		if err := writeFileAtomic(s.blockPath(h), append(raw, '\n'), 0o644); err != nil {
			return AddResult{Hash: h}, err
		}
	}
	e := &entry{block: b, hash: h, parent: b.Header.Prev, height: b.Header.Height, time: b.Header.Time, state: state}
	s.blocks[h] = e
	res := AddResult{Hash: h}
	head := s.blocks[s.canon[len(s.canon)-1]]
	if e.height > head.height || (e.height == head.height && bytes.Compare(h[:], head.hash[:]) < 0) {
		s.reorgLocked(e, &res)
	}
	return res, nil
}

// parentInfoLocked builds the Parent view for a stored entry.
func (s *Store) parentInfoLocked(e *entry) Parent {
	p := Parent{Hash: e.hash, Height: e.height, Time: e.time, State: e.state}
	for cur, n := e, s.P.RecentSignerWindow(); n > 0 && cur.block != nil; n-- {
		p.RecentSigners = append(p.RecentSigners, cur.block.Header.Signer)
		cur = s.blocks[cur.parent]
	}
	return p
}

// reorgLocked makes e the canonical head, filling in what changed.
func (s *Store) reorgLocked(e *entry, res *AddResult) {
	var path []*entry // from the new head back to the common ancestor (exclusive)
	cur := e
	for int(cur.height) >= len(s.canon) || s.canon[cur.height] != cur.hash {
		path = append(path, cur)
		cur = s.blocks[cur.parent]
	}
	// cur is the common ancestor
	for _, old := range s.canon[cur.height+1:] {
		ob := s.blocks[old].block
		res.Orphaned = append(res.Orphaned, ob)
		for _, pe := range ob.Payloads {
			delete(s.ids, pe.ID())
		}
	}
	s.canon = s.canon[:cur.height+1]
	for i := len(path) - 1; i >= 0; i-- {
		n := path[i]
		s.canon = append(s.canon, n.hash)
		res.Adopted = append(res.Adopted, n.block)
		for _, pe := range n.block.Payloads {
			s.ids[pe.ID()] = n.hash
		}
	}
	res.NewHead = true
}

// Head returns the canonical head's hash and height.
func (s *Store) Head() (Hash, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.canon[len(s.canon)-1], uint64(len(s.canon) - 1)
}

// HeadParent describes the canonical head as the parent of the next block.
func (s *Store) HeadParent() Parent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.parentInfoLocked(s.blocks[s.canon[len(s.canon)-1]])
}

// Block returns any stored block (canonical or not) by hash. The genesis has none.
func (s *Store) Block(h Hash) (*Block, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.blocks[h]
	if !ok || e.block == nil {
		return nil, false
	}
	return e.block, true
}

// Has reports whether h (or the genesis) is stored.
func (s *Store) Has(h Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.blocks[h]
	return ok
}

// HashAt returns the canonical block hash at a height.
func (s *Store) HashAt(height uint64) (Hash, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if height >= uint64(len(s.canon)) {
		return Hash{}, false
	}
	return s.canon[height], true
}

// Range returns up to limit canonical blocks starting at height from (>= 1).
func (s *Store) Range(from uint64, limit int) []*Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if from < 1 {
		from = 1
	}
	var out []*Block
	for h := from; h < uint64(len(s.canon)) && len(out) < limit; h++ {
		out = append(out, s.blocks[s.canon[h]].block)
	}
	return out
}

// OnChain reports whether a payload is already in the canonical chain.
func (s *Store) OnChain(id Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.ids[id]
	return ok
}

// Latest returns up to n canonical blocks, newest first.
func (s *Store) Latest(n int) []*Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*Block
	for h := len(s.canon) - 1; h >= 1 && len(out) < n; h-- {
		out = append(out, s.blocks[s.canon[h]].block)
	}
	return out
}

// Verify replays the whole canonical chain from the genesis with full
// validation, independent of what Open accepted, and returns its height.
func (s *Store) Verify() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g := s.blocks[s.P.GenesisHash]
	parent := Parent{Hash: g.hash, Height: 0, Time: g.time, State: s.P.Initial}
	var signers []string
	for h := 1; h < len(s.canon); h++ {
		b := s.blocks[s.canon[h]].block
		recent := signers
		if w := s.P.RecentSignerWindow(); len(recent) > w {
			recent = recent[len(recent)-w:]
		}
		parent.RecentSigners = reverse(recent)
		state, err := s.P.ValidateBlock(b, parent, s.now())
		if err != nil {
			return uint64(h - 1), fmt.Errorf("block %d (%s): %w", h, b.Hash().Short(), err)
		}
		signers = append(signers, b.Header.Signer)
		parent = Parent{Hash: b.Hash(), Height: b.Header.Height, Time: b.Header.Time, State: state}
	}
	return uint64(len(s.canon) - 1), nil
}

// HeadState returns the authority set after the canonical head.
func (s *Store) HeadState() *State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blocks[s.canon[len(s.canon)-1]].state
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
