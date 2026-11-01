package chain

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"eidchain/internal/tsa"
)

// MaxClockSkew is how far ahead of local time a block timestamp may be.
const MaxClockSkew = 5 * time.Minute

// MaxTimestampSkew is how far a block's timestamp token may be from its time.
const MaxTimestampSkew = 5 * time.Minute

// MaxBlockBytes caps a block's JSON. It must stay below what nodes accept when a
// block is pushed to them (16 MiB, and the same in nginx) or a valid block could
// never spread: producers stop filling a block here and leave the rest pending.
const MaxBlockBytes = 8 << 20

// PayloadInfo describes a payload that passed validation.
type PayloadInfo struct {
	ID          Hash
	Cert        *x509.Certificate
	Subject     string
	Serial      string
	SigningTime time.Time // claimed by the signer, informational
}

// VerifyPayload applies the consensus rules to one payload: size, valid UTF-8
// JSON object, valid detached CAdES signature over the exact bytes, signer
// certificate chaining to the genesis trust anchors (judged at time at) and,
// if the genesis requires it, the non-repudiation key usage.
func (p *Params) VerifyPayload(e PayloadEntry, at time.Time) (*PayloadInfo, error) {
	if len(e.Payload) == 0 || len(e.Payload) > p.Rules.MaxPayloadBytes {
		return nil, fmt.Errorf("payload must be 1..%d bytes", p.Rules.MaxPayloadBytes)
	}
	if !utf8.ValidString(e.Payload) {
		return nil, errors.New("payload is not valid UTF-8")
	}
	if err := CheckPayloadJSON(e.Payload); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(sig) == 0 || len(sig) > 64*1024 {
		return nil, errors.New("signature is not valid base64 (or too large)")
	}
	var untrusted error
	s, err := verifyDetached(sig, []byte(e.Payload), func(c *x509.Certificate) error {
		if err := p.Trust.Verify(c, at); err != nil {
			untrusted = fmt.Errorf("signer certificate not trusted: %w (issuer %q; the genesis trusts %s; the issuer's certificate may be published at %v)",
				err, CertName2(c.Issuer.CommonName, c.Issuer.Organization), p.Trust.Names(), c.IssuingCertificateURL)
			return untrusted
		}
		return nil
	})
	if untrusted != nil {
		return nil, untrusted
	}
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	if p.Rules.RequireNonRepudiation && s.Cert.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		return nil, errors.New("signer certificate lacks the non-repudiation key usage (is this the authentication certificate?)")
	}
	return &PayloadInfo{
		ID:          e.ID(),
		Cert:        s.Cert,
		Subject:     SubjectName(s.Cert),
		Serial:      s.Cert.SerialNumber.Text(16),
		SigningTime: s.SigningTime,
	}, nil
}

// checkTimestamp applies the block-timestamps feature: from its height a block must
// carry a token over its content hash, committed to by the block hash, from an
// authority whose time agrees with the block's. Below that height it must have no
// token. The certificate chain is judged at the token's own time, so the verdict
// does not depend on when a block is checked.
func (p *Params) checkTimestamp(b *Block) error {
	h := b.Header
	if !p.Features.Active(FeatureBlockTimestamps, h.Height) {
		if b.Timestamp != "" || h.TimestampHash != nil {
			return errors.New("a timestamp is not allowed at this height")
		}
		return nil
	}
	if b.Timestamp == "" || h.TimestampHash == nil {
		return errors.New("the block has no timestamp")
	}
	token, err := base64.StdEncoding.DecodeString(b.Timestamp)
	if err != nil {
		return errors.New("timestamp is not valid base64")
	}
	if sha256.Sum256(token) != *h.TimestampHash {
		return errors.New("timestampHash does not match the timestamp")
	}
	info, err := tsa.Verify(token, b.ContentHash(), p.TSARoots)
	if err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if d := info.Time.Sub(time.Unix(h.Time, 0)).Abs(); d > MaxTimestampSkew {
		return fmt.Errorf("the timestamp is %s away from the block time", d.Round(time.Second))
	}
	return nil
}

// BlockTimestamp reads the token of a block that passed validation.
func (p *Params) BlockTimestamp(b *Block) (tsa.Info, bool) {
	token, err := base64.StdEncoding.DecodeString(b.Timestamp)
	if err != nil || len(token) == 0 {
		return tsa.Info{}, false
	}
	info, err := tsa.Verify(token, b.ContentHash(), p.TSARoots)
	return info, err == nil
}

// Parent describes the block a new block builds on.
type Parent struct {
	Hash   Hash
	Height uint64
	Time   int64
	// State is the authority set after the parent: the keys that are valid
	// signers (of the block and of any rotation approvals) for the child.
	State *State
	// RecentSigners are the signers of the last RecentSignerWindow blocks up to
	// and including the parent (newest first). The genesis has no signer.
	RecentSigners []string
}

// CanSign reports whether the authority key id may sign a child of parent.
func (p *Params) CanSign(id string, parent Parent) bool {
	if !parent.State.Has(id) {
		return false
	}
	for _, s := range parent.RecentSigners {
		if s == id {
			return false
		}
	}
	return true
}

// ValidateBlock applies every consensus rule to b given its parent and returns
// the authority state after b (rotations take effect from the next block). now
// is only used to reject timestamps too far in the future.
func (p *Params) ValidateBlock(b *Block, parent Parent, now time.Time) (*State, error) {
	h := b.Header
	if want := p.Features.VersionAt(h.Height); h.Version != want {
		return nil, fmt.Errorf("block version %d at height %d, expected %d", h.Version, h.Height, want)
	}
	if h.Height != parent.Height+1 {
		return nil, fmt.Errorf("height %d does not follow parent height %d", h.Height, parent.Height)
	}
	if h.Prev != parent.Hash {
		return nil, errors.New("prev does not match the parent hash")
	}
	if h.Time < parent.Time {
		return nil, errors.New("block time precedes its parent")
	}
	if h.Time > now.Add(MaxClockSkew).Unix() {
		return nil, errors.New("block time is too far in the future")
	}
	if !parent.State.Has(h.Signer) {
		return nil, errors.New("signer is not a currently valid authority")
	}
	if !p.CanSign(h.Signer, parent) {
		return nil, fmt.Errorf("signer signed one of the last %d blocks", p.RecentSignerWindow())
	}
	if h.PayloadCount != len(b.Payloads) || h.RotationCount != len(b.Rotations) {
		return nil, errors.New("payloadCount or rotationCount does not match the block body")
	}
	if len(b.Payloads)+len(b.Rotations) == 0 {
		return nil, errors.New("a block needs at least one payload or rotation")
	}
	if len(b.Rotations) > p.Rules.MaxRotationsPerBlock {
		return nil, errors.New("too many rotations in one block")
	}
	root, err := PayloadsRoot(b.Payloads)
	if err != nil {
		return nil, err
	}
	if root != h.PayloadsRoot {
		return nil, errors.New("payloadsRoot does not match the payloads")
	}
	if RotationsRoot(b.Rotations) != h.RotationsRoot {
		return nil, errors.New("rotationsRoot does not match the rotations")
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil {
		return nil, errors.New("block signature is not valid base64")
	}
	hash := b.Hash()
	if !ecdsa.VerifyASN1(parent.State.Keys[h.Signer], hash[:], sig) {
		return nil, errors.New("block signature is invalid")
	}
	if raw, err := json.Marshal(b); err != nil || len(raw) > MaxBlockBytes {
		return nil, fmt.Errorf("block is larger than %d bytes", MaxBlockBytes)
	}
	if err := p.checkTimestamp(b); err != nil {
		return nil, err
	}
	at := time.Unix(h.Time, 0)
	seen := map[Hash]bool{}
	for i, e := range b.Payloads {
		info, err := p.VerifyPayload(e, at)
		if err != nil {
			return nil, fmt.Errorf("payload %d: %w", i, err)
		}
		if seen[info.ID] {
			return nil, fmt.Errorf("payload %d duplicates an earlier payload in the block", i)
		}
		seen[info.ID] = true
	}
	// Key rotations: approved by keys valid at the parent, applied in order.
	next := parent.State
	for i, r := range b.Rotations {
		if next, err = p.ApplyRotation(parent.State, next, r); err != nil {
			return nil, fmt.Errorf("rotation %d: %w", i, err)
		}
	}
	return next, nil
}
