package tsa

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"eidchain/internal/chain"
)

// Stamp is a verified token.
type Stamp struct {
	Token []byte
	Info  Info
}

// Book keeps verified tokens under <data>/timestamps/<block hash>.json, at most one
// per authority per block: the earliest, which proves the most. Anyone may offer
// a token, but only a real one for that hash gets in.
type Book struct {
	mu     sync.RWMutex
	dir    string
	roots  *x509.CertPool
	blocks map[chain.Hash][]Stamp
}

// OpenBook loads the tokens in a data directory. Tokens are verified again, and
// skipped lists what failed.
func OpenBook(dataDir string, roots *x509.CertPool) (*Book, []string) {
	b := &Book{dir: filepath.Join(dataDir, "timestamps"), roots: roots, blocks: map[chain.Hash][]Stamp{}}
	paths, _ := filepath.Glob(filepath.Join(b.dir, "*.json"))
	var skipped []string
	for _, path := range paths {
		name := filepath.Base(path)
		hash, err := chain.ParseHash(strings.TrimSuffix(name, ".json"))
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		raw, err := os.ReadFile(path)
		var tokens [][]byte
		if err == nil {
			err = chain.StrictUnmarshal(raw, &tokens)
		}
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		for _, t := range tokens {
			info, err := Verify(t, hash, roots)
			if err != nil {
				skipped = append(skipped, fmt.Sprintf("%s: %v", name, err))
				continue
			}
			b.blocks[hash] = append(b.blocks[hash], Stamp{t, info})
		}
	}
	return b, skipped
}

// Add verifies a token and keeps it if it is new or earlier than the one held
// from the same authority. It reports whether anything changed.
func (b *Book) Add(hash chain.Hash, token []byte) (bool, error) {
	info, err := Verify(token, hash, b.roots)
	if err != nil {
		return false, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	list := append([]Stamp(nil), b.blocks[hash]...)
	replaced := false
	for i, s := range list {
		if s.Info.Authority == info.Authority {
			if !info.Time.Before(s.Info.Time) {
				return false, nil
			}
			list[i] = Stamp{token, info}
			replaced = true
		}
	}
	if !replaced {
		list = append(list, Stamp{token, info})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Info.Time.Before(list[j].Info.Time) })
	tokens := make([][]byte, len(list))
	for i, s := range list {
		tokens[i] = s.Token
	}
	raw, err := json.Marshal(tokens)
	if err != nil {
		return false, err
	}
	if err := chain.WriteFileAtomic(filepath.Join(b.dir, hash.String()+".json"), append(raw, '\n'), 0o644); err != nil {
		return false, err
	}
	b.blocks[hash] = list
	return true, nil
}

// List returns a block's tokens, earliest first.
func (b *Book) List(hash chain.Hash) []Stamp {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]Stamp(nil), b.blocks[hash]...)
}

// Has reports whether a block has a token from an authority.
func (b *Book) Has(hash chain.Hash, authority string) bool {
	for _, s := range b.List(hash) {
		if s.Info.Authority == authority {
			return true
		}
	}
	return false
}
