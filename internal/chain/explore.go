package chain

import (
	"crypto/x509"
	"errors"

	"golang.org/x/crypto/ocsp"
)

// Window returns up to n canonical blocks with a height below before, newest
// first. before == 0 starts at the head.
func (s *Store) Window(before uint64, n int) []*Block {
	s.mu.RLock()
	defer s.mu.RUnlock()
	top := uint64(len(s.canon)) // exclusive upper bound on heights
	if before != 0 && before < top {
		top = before
	}
	var out []*Block
	for h := top; h > 1 && len(out) < n; h-- {
		out = append(out, s.blocks[s.canon[h-1]].block)
	}
	return out
}

// AllHashes lists every stored block and every payload on the canonical chain.
func (s *Store) AllHashes() (blocks, payloads []Hash) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for h, e := range s.blocks {
		if e.block != nil {
			blocks = append(blocks, h)
		}
	}
	for id := range s.ids {
		payloads = append(payloads, id)
	}
	return blocks, payloads
}

// BlockAt returns the canonical block at a height (>= 1).
func (s *Store) BlockAt(height uint64) (*Block, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if height < 1 || height >= uint64(len(s.canon)) {
		return nil, false
	}
	return s.blocks[s.canon[height]].block, true
}

// IsCanonical reports whether h is on the canonical chain.
func (s *Store) IsCanonical(h Hash) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.blocks[h]
	return ok && e.block != nil && int(e.height) < len(s.canon) && s.canon[e.height] == h
}

// FindPayload locates a payload on the canonical chain by its ID.
func (s *Store) FindPayload(id Hash) (*Block, int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	bh, ok := s.ids[id]
	if !ok {
		return nil, 0, false
	}
	b := s.blocks[bh].block
	for i, p := range b.Payloads {
		if p.ID() == id {
			return b, i, true
		}
	}
	return nil, 0, false
}

// RotationEvent is a rotation as recorded in a canonical block.
type RotationEvent struct {
	Height   uint64
	Block    Hash
	Time     int64
	Signer   string // authority that signed the block carrying it
	Rotation Rotation
}

// RotationHistory lists every rotation on the canonical chain, oldest first.
func (s *Store) RotationHistory() []RotationEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []RotationEvent
	for h := 1; h < len(s.canon); h++ {
		b := s.blocks[s.canon[h]].block
		for _, r := range b.Rotations {
			out = append(out, RotationEvent{Height: b.Header.Height, Block: s.canon[h], Time: b.Header.Time, Signer: b.Header.Signer, Rotation: r})
		}
	}
	return out
}

// OCSPInfo is what an explorer shows about a stored OCSP response.
type OCSPInfo struct {
	Status            string `json:"status"` // good, revoked, unknown
	ProducedAt        int64  `json:"producedAt"`
	ThisUpdate        int64  `json:"thisUpdate"`
	NextUpdate        int64  `json:"nextUpdate,omitempty"`
	SignatureVerified bool   `json:"signatureVerified"`
	Bytes             int    `json:"bytes"`
}

// InspectOCSP decodes a stored OCSP response. If the issuer is known the
// responder's signature is verified too; otherwise the fields are shown as
// unverified.
func InspectOCSP(raw []byte, cert, issuer *x509.Certificate) (OCSPInfo, error) {
	info := OCSPInfo{Bytes: len(raw)}
	var r *ocsp.Response
	var err error
	if issuer != nil {
		if r, err = ocsp.ParseResponseForCert(raw, cert, issuer); err == nil {
			// A response is only "verified" if its signer may answer for this CA,
			// judged when it was produced: stored responses outlive their responders.
			info.SignatureVerified = checkResponder(r, issuer, r.ProducedAt) == nil
		}
	}
	if r == nil {
		if r, err = ocsp.ParseResponse(raw, nil); err != nil {
			return info, err
		}
	}
	switch r.Status {
	case ocsp.Good:
		info.Status = "good"
	case ocsp.Revoked:
		info.Status = "revoked"
	default:
		info.Status = "unknown"
	}
	info.ProducedAt, info.ThisUpdate = r.ProducedAt.Unix(), r.ThisUpdate.Unix()
	if !r.NextUpdate.IsZero() {
		info.NextUpdate = r.NextUpdate.Unix()
	}
	if cert != nil && r.SerialNumber != nil && r.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return info, errors.New("OCSP response is for a different certificate")
	}
	return info, nil
}
