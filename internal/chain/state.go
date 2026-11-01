package chain

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// State is the authority set in force after a given block. Rotations change
// it, so every block is validated against the state of its parent: a key is
// "valid at the time" if it is in the parent's state.
type State struct {
	IDs  []string // key IDs, in slot order (a replacement keeps the old key's slot)
	Keys map[string]*ecdsa.PublicKey
	Seq  uint64 // rotations applied so far on this branch
}

// Has reports whether id is an authority in this state.
func (s *State) Has(id string) bool { _, ok := s.Keys[id]; return ok }

func (s *State) clone() *State {
	c := &State{IDs: append([]string(nil), s.IDs...), Keys: make(map[string]*ecdsa.PublicKey, len(s.Keys)), Seq: s.Seq}
	for k, v := range s.Keys {
		c.Keys[k] = v
	}
	return c
}

// replace returns a copy of s with oldID's slot given to the new key.
func (s *State) replace(oldID, newID string, pub *ecdsa.PublicKey) *State {
	c := s.clone()
	for i, id := range c.IDs {
		if id == oldID {
			c.IDs[i] = newID
		}
	}
	delete(c.Keys, oldID)
	c.Keys[newID] = pub
	c.Seq++
	return c
}

// ApplyRotation checks r and returns the state after it. signers is the state
// whose keys may approve (the parent's state); working is the state the change
// applies to (it differs from signers only after earlier rotations in the same block).
func (p *Params) ApplyRotation(signers, working *State, r Rotation) (*State, error) {
	c := r.Change
	if c.Type != "replace" {
		return nil, fmt.Errorf("unknown rotation type %q", c.Type)
	}
	if c.Chain != p.GenesisHash {
		return nil, errors.New("rotation is for a different chain")
	}
	if c.Seq != working.Seq {
		return nil, fmt.Errorf("rotation seq %d, expected %d", c.Seq, working.Seq)
	}
	if !working.Has(c.Old) {
		return nil, errors.New("rotation replaces a key that is not an authority")
	}
	pub, err := DecodePublicKey(c.NewKey)
	if err != nil {
		return nil, fmt.Errorf("new key: %w", err)
	}
	newID, _ := KeyID(pub)
	if working.Has(newID) {
		return nil, errors.New("new key is already an authority")
	}
	if err := p.checkApprovals(signers, r); err != nil {
		return nil, err
	}
	return working.replace(c.Old, newID, pub), nil
}

// checkApprovals demands at least RotationQuorum distinct, valid signatures
// from keys that are authorities in signers.
func (p *Params) checkApprovals(signers *State, r Rotation) error {
	h := r.Change.Hash()
	prev := ""
	for i, s := range r.Signatures {
		if i > 0 && s.Signer <= prev {
			return errors.New("rotation signatures must be sorted by signer and distinct")
		}
		prev = s.Signer
		pub, ok := signers.Keys[s.Signer]
		if !ok {
			return fmt.Errorf("rotation signed by %s…, which is not a currently valid authority", short(s.Signer))
		}
		sig, err := decodeB64(s.Signature)
		if err != nil || !ecdsa.VerifyASN1(pub, h[:], sig) {
			return fmt.Errorf("invalid rotation signature from %s…", short(s.Signer))
		}
	}
	if len(r.Signatures) < p.Rules.RotationQuorum {
		return fmt.Errorf("rotation has %d approvals, %d required", len(r.Signatures), p.Rules.RotationQuorum)
	}
	return nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
