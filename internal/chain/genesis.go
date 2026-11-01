package chain

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// NewGenesis assembles a genesis document. The authorities' public keys, the
// trusted CA certificates (PEM) and the message are all fixed forever by the
// resulting hash.
func NewGenesis(message string, authorities []Authority, trustAnchorsPEM []string, created time.Time) (*Genesis, error) {
	g := &Genesis{
		Type:         "eidchain-genesis",
		Version:      Version,
		Created:      created.UTC().Unix(),
		Message:      message,
		Authorities:  authorities,
		TrustAnchors: trustAnchorsPEM,
		Rules:        Rules{RequireNonRepudiation: true, MaxPayloadBytes: DefaultMaxPayloadBytes, RotationQuorum: len(authorities)/2 + 1, MaxRotationsPerBlock: 8},
	}
	if _, err := NewParams(g); err != nil {
		return nil, err
	}
	return g, nil
}

// SaveGenesis writes the genesis file (pretty printed; the hash does not depend on layout).
func SaveGenesis(path string, g *Genesis) error {
	raw, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, append(raw, '\n'), 0o644)
}

// LoadGenesis reads and validates a genesis file.
func LoadGenesis(path string) (*Genesis, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGenesis(raw)
}

// ParseGenesis decodes genesis JSON, rejecting unknown fields so that two
// nodes cannot disagree on what a hash covers.
func ParseGenesis(raw []byte) (*Genesis, error) {
	var g Genesis
	if err := StrictUnmarshal(raw, &g); err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	if _, err := NewParams(&g); err != nil {
		return nil, err
	}
	return &g, nil
}

// Params is a validated genesis plus everything derived from it.
type Params struct {
	Genesis     *Genesis
	GenesisHash Hash
	// Initial is the authority set at the genesis; rotations evolve it per block.
	Initial *State
	Trust   *TrustStore
	Rules   Rules
}

// NewParams validates g and prepares it for use.
func NewParams(g *Genesis) (*Params, error) {
	if g.Type != "eidchain-genesis" {
		return nil, errors.New("genesis: wrong type")
	}
	if g.Version != Version {
		return nil, fmt.Errorf("genesis: unsupported version %d", g.Version)
	}
	if len(g.Authorities) == 0 {
		return nil, errors.New("genesis: at least one authority is required")
	}
	p := &Params{Genesis: g, GenesisHash: g.Hash(), Initial: &State{Keys: map[string]*ecdsa.PublicKey{}}, Rules: g.Rules}
	for i, a := range g.Authorities {
		pub, err := DecodePublicKey(a.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("genesis: authority %d: %w", i, err)
		}
		id, _ := KeyID(pub)
		if _, dup := p.Initial.Keys[id]; dup {
			return nil, fmt.Errorf("genesis: authority %d duplicates an earlier key", i)
		}
		p.Initial.Keys[id] = pub
		p.Initial.IDs = append(p.Initial.IDs, id)
	}
	if g.Rules.MaxPayloadBytes <= 0 || g.Rules.MaxPayloadBytes > 1<<20 {
		return nil, errors.New("genesis: rules.maxPayloadBytes out of range")
	}
	if q := g.Rules.RotationQuorum; q < 1 || q > len(g.Authorities) {
		return nil, fmt.Errorf("genesis: rules.rotationQuorum must be between 1 and %d", len(g.Authorities))
	}
	if g.Rules.MaxRotationsPerBlock < 1 || g.Rules.MaxRotationsPerBlock > 64 {
		return nil, errors.New("genesis: rules.maxRotationsPerBlock must be between 1 and 64")
	}
	ts, err := NewTrustStore(g.TrustAnchors)
	if err != nil {
		return nil, fmt.Errorf("genesis: %w", err)
	}
	p.Trust = ts
	return p, nil
}

// RecentSignerWindow is how many preceding blocks a signer must not appear in
// (Clique rule): a key may sign at most one block in any floor(N/2)+1
// consecutive blocks, so rewriting history takes a majority of the keys.
func (p *Params) RecentSignerWindow() int { return len(p.Initial.IDs) / 2 }
