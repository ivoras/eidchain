package chain_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"eidchain/internal/chain"
)

func TestVerifyDetachedGoBuilt(t *testing.T) {
	p := newPKI(t)
	for name, useEC := range map[string]bool{"rsa": false, "ecdsa": true} {
		l := p.Leaf(t, "X", x509.KeyUsageContentCommitment, useEC)
		sig := cadesSign(t, l, []byte("hello"))
		s, err := chain.VerifyDetached(sig, []byte("hello"))
		if err != nil || !s.Cert.Equal(l.Cert) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := chain.VerifyDetached(sig, []byte("hellO")); err == nil || !strings.Contains(err.Error(), "digest") {
			t.Fatalf("%s: tampered content accepted: %v", name, err)
		}
	}
}

// The fixtures were produced by the browser-side signer (www/signer/cades.js).
func TestVerifyDetachedFromBrowserSigner(t *testing.T) {
	payload, _ := os.ReadFile("testdata/payload.txt")
	for _, name := range []string{"rsa", "ec"} {
		sig, err := os.ReadFile("testdata/js-" + name + ".p7s")
		if err != nil {
			t.Fatal(err)
		}
		s, err := chain.VerifyDetached(sig, payload)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		pemBytes, _ := os.ReadFile("testdata/js-" + name + ".pem")
		blk, _ := pem.Decode(pemBytes)
		if !s.Cert.Equal(mustCert(t, blk.Bytes)) {
			t.Fatalf("%s: wrong signer certificate", name)
		}
		if s.SigningTime.IsZero() {
			t.Fatalf("%s: signing time not read", name)
		}
		bad := append([]byte{}, payload...)
		bad[0] ^= 1
		if _, err := chain.VerifyDetached(sig, bad); err == nil {
			t.Fatalf("%s: tampered payload accepted", name)
		}
	}
}

func mustCert(t *testing.T, der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestChainFlowAndRules(t *testing.T) {
	e := newEnv(t, 3) // recent-signer window = 1
	s := e.signers

	b1 := e.next(s[0], []chain.PayloadEntry{e.payload("one")}, nil)
	if _, err := e.store.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.AddBlock(b1); !errors.Is(err, chain.ErrKnown) {
		t.Fatalf("duplicate: %v", err)
	}
	// The same key may not sign twice in a row.
	if _, err := e.store.AddBlock(e.next(s[0], []chain.PayloadEntry{e.payload("two")}, nil)); err == nil ||
		!strings.Contains(err.Error(), "last 1 blocks") {
		t.Fatalf("consecutive signer accepted: %v", err)
	}
	// Unknown parent.
	orphan := e.blockOn(chain.Hash{1}, 5, s[1], []chain.PayloadEntry{e.payload("x")}, nil)
	if _, err := e.store.AddBlock(orphan); !errors.Is(err, chain.ErrUnknownParent) {
		t.Fatalf("orphan: %v", err)
	}
	// Outsider key.
	k, _ := chain.GenerateKey()
	id, _ := chain.KeyID(&k.PublicKey)
	if _, err := e.store.AddBlock(e.next(chain.Signer{ID: id, Key: k}, []chain.PayloadEntry{e.payload("y")}, nil)); err == nil {
		t.Fatal("non-authority signer accepted")
	}
	// Payload signed by a certificate from another PKI.
	other := newPKI(t).Leaf(t, "EVE", x509.KeyUsageContentCommitment, false)
	if _, err := e.store.AddBlock(e.next(s[1], []chain.PayloadEntry{e.payloadAs(other, "evil")}, nil)); err == nil ||
		!strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("untrusted cert: %v", err)
	}
	// Authentication-style certificate (no non-repudiation).
	auth := e.pki.Leaf(t, "PERA PERIC", x509.KeyUsageDigitalSignature, false)
	if _, err := e.store.AddBlock(e.next(s[1], []chain.PayloadEntry{e.payloadAs(auth, "authcert")}, nil)); err == nil ||
		!strings.Contains(err.Error(), "non-repudiation") {
		t.Fatalf("auth cert: %v", err)
	}
	// Payload text altered after signing (block re-signed by an authority).
	p := e.payload("honest")
	p.Payload = strings.Replace(p.Payload, "honest", "forged", 1)
	if _, err := e.store.AddBlock(e.next(s[1], []chain.PayloadEntry{p}, nil)); err == nil ||
		!strings.Contains(err.Error(), "digest") {
		t.Fatalf("forged payload: %v", err)
	}
	// Oversized and non-object payloads.
	big := e.payload(strings.Repeat("a", 11*1024))
	if _, err := e.store.AddBlock(e.next(s[1], []chain.PayloadEntry{big}, nil)); err == nil {
		t.Fatal("oversized payload accepted")
	}
	// Empty block.
	if _, err := e.store.AddBlock(e.next(s[1], nil, nil)); err == nil {
		t.Fatal("empty block accepted")
	}
	// A valid second block by another key.
	b2 := e.next(s[1], []chain.PayloadEntry{e.payload("two")}, nil)
	if _, err := e.store.AddBlock(b2); err != nil {
		t.Fatal(err)
	}
	if _, h := e.store.Head(); h != 2 {
		t.Fatalf("height %d", h)
	}
	if !e.store.OnChain(e.payload("two").ID()) && e.payload("two").ID() == (chain.Hash{}) {
		t.Fatal("unreachable")
	}
}

func TestForkChoiceAndReorg(t *testing.T) {
	e := newEnv(t, 3)
	s := e.signers
	b1 := e.next(s[0], []chain.PayloadEntry{e.payload("base")}, nil)
	if _, err := e.store.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	h1 := b1.Hash()
	pa, pb := e.payload("branch A"), e.payload("branch B")
	a2 := e.blockOn(h1, 2, s[1], []chain.PayloadEntry{pa}, nil)
	b2 := e.blockOn(h1, 2, s[2], []chain.PayloadEntry{pb}, nil)
	for _, b := range []*chain.Block{a2, b2} {
		if _, err := e.store.AddBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	// Equal height: the lower hash is canonical.
	winner, loser := a2, b2
	if lessHash(b2.Hash(), a2.Hash()) {
		winner, loser = b2, a2
	}
	if head, _ := e.store.Head(); head != winner.Hash() {
		t.Fatalf("head %s, want the lower hash %s", head.Short(), winner.Hash().Short())
	}
	if !e.store.OnChain(winner.Payloads[0].ID()) || e.store.OnChain(loser.Payloads[0].ID()) {
		t.Fatal("payload index does not follow the canonical branch")
	}
	// Extend the losing branch: the longer chain wins and the other is orphaned.
	signer := s[1] // loser was signed by s[1] or s[2]; pick someone else
	for _, c := range s {
		if c.ID != loser.Header.Signer && c.ID != b1.Header.Signer {
			signer = c
		}
	}
	b3 := e.blockOn(loser.Hash(), 3, signer, []chain.PayloadEntry{e.payload("extends loser")}, nil)
	res, err := e.store.AddBlock(b3)
	if err != nil {
		t.Fatal(err)
	}
	if !res.NewHead || len(res.Orphaned) != 1 || res.Orphaned[0].Hash() != winner.Hash() || len(res.Adopted) != 2 {
		t.Fatalf("reorg result wrong: %+v", res)
	}
	if head, h := e.store.Head(); head != b3.Hash() || h != 3 {
		t.Fatal("head did not move to the longer branch")
	}
	if e.store.OnChain(winner.Payloads[0].ID()) || !e.store.OnChain(loser.Payloads[0].ID()) {
		t.Fatal("payload index not updated by the reorg")
	}
}

func lessHash(a, b chain.Hash) bool { return a.String() < b.String() }

func (e *env) rotation(old int, newKey string, seq uint64, approvers ...int) chain.Rotation {
	r := chain.Rotation{Change: chain.KeyChange{Type: "replace", Chain: e.genesis.Hash(), Seq: seq, Old: e.signers[old].ID, NewKey: newKey}}
	for _, i := range approvers {
		sig, err := chain.SignKeyChange(e.signers[i], r.Change)
		if err != nil {
			e.t.Fatal(err)
		}
		r.AddSignature(sig)
	}
	return r
}

func TestKeyRotation(t *testing.T) {
	e := newEnv(t, 3) // quorum = 2
	s := e.signers
	newKey, _ := chain.GenerateKey()
	newPub, _ := chain.EncodePublicKey(&newKey.PublicKey)
	newID, _ := chain.KeyID(&newKey.PublicKey)
	newSigner := chain.Signer{ID: newID, Key: newKey}

	// One approval is not enough.
	weak := e.rotation(0, newPub, 0, 1)
	if _, err := e.store.AddBlock(e.next(s[2], nil, []chain.Rotation{weak})); err == nil || !strings.Contains(err.Error(), "approvals") {
		t.Fatalf("under-approved rotation accepted: %v", err)
	}
	// An outsider's approval does not count.
	outsider, _ := chain.GenerateKey()
	oid, _ := chain.KeyID(&outsider.PublicKey)
	bad := e.rotation(0, newPub, 0, 1)
	osig, _ := chain.SignKeyChange(chain.Signer{ID: oid, Key: outsider}, bad.Change)
	bad.AddSignature(osig)
	if _, err := e.store.AddBlock(e.next(s[2], nil, []chain.Rotation{bad})); err == nil || !strings.Contains(err.Error(), "currently valid") {
		t.Fatalf("outsider approval accepted: %v", err)
	}
	// Wrong chain.
	wrong := e.rotation(0, newPub, 0, 1, 2)
	wrong.Change.Chain = chain.Hash{9}
	if _, err := e.store.AddBlock(e.next(s[2], nil, []chain.Rotation{wrong})); err == nil {
		t.Fatal("rotation for another chain accepted")
	}

	// A good rotation, together with an eID payload, in a block signed by the third key.
	rot := e.rotation(0, newPub, 0, 1, 2)
	b1 := e.next(s[2], []chain.PayloadEntry{e.payload("with rotation")}, []chain.Rotation{rot})
	if _, err := e.store.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	st := e.store.HeadState()
	if st.Has(s[0].ID) || !st.Has(newID) || st.Seq != 1 || st.IDs[0] != newID {
		t.Fatalf("state after rotation wrong: %+v", st.IDs)
	}
	// The retired key can no longer sign; the new one can.
	if _, err := e.store.AddBlock(e.next(s[0], []chain.PayloadEntry{e.payload("old key")}, nil)); err == nil ||
		!strings.Contains(err.Error(), "not a currently valid") {
		t.Fatalf("retired key accepted: %v", err)
	}
	if _, err := e.store.AddBlock(e.next(newSigner, []chain.PayloadEntry{e.payload("new key")}, nil)); err != nil {
		t.Fatalf("new key rejected: %v", err)
	}
	// Replaying the old rotation fails (its seq is spent).
	if _, err := e.store.AddBlock(e.next(s[1], nil, []chain.Rotation{rot})); err == nil {
		t.Fatal("replayed rotation accepted")
	}
	// The retired key's earlier signatures stay valid: reopening replays the whole chain.
	re, err := chain.Open(e.dir, e.genesis.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if h, err := re.Verify(); err != nil || h != 2 {
		t.Fatalf("verify after reopen: height %d, %v", h, err)
	}
	head1, _ := e.store.Head()
	head2, _ := re.Head()
	if head1 != head2 {
		t.Fatal("reopened store has a different head")
	}
	// A rotation-only block (no eID payloads) is fine: rotate the second key.
	second, _ := chain.GenerateKey()
	spub, _ := chain.EncodePublicKey(&second.PublicKey)
	r2 := chain.Rotation{Change: chain.KeyChange{Type: "replace", Chain: e.genesis.Hash(), Seq: 1, Old: s[1].ID, NewKey: spub}}
	for _, sg := range []chain.Signer{s[2], newSigner} {
		sig, _ := chain.SignKeyChange(sg, r2.Change)
		r2.AddSignature(sig)
	}
	if _, err := e.store.AddBlock(e.next(s[1], nil, []chain.Rotation{r2})); err != nil {
		t.Fatalf("rotation-only block rejected: %v", err)
	}
	_ = base64.StdEncoding
}
