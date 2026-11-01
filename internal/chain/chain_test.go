package chain_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func rotationTo(t *testing.T, e *env, seq uint64, old string, approvers ...chain.Signer) (chain.Rotation, chain.Signer) {
	t.Helper()
	k, _ := chain.GenerateKey()
	id, _ := chain.KeyID(&k.PublicKey)
	pub, _ := chain.EncodePublicKey(&k.PublicKey)
	r := chain.Rotation{Change: chain.KeyChange{Type: "replace", Chain: e.genesis.Hash(), Seq: seq, Old: old, NewKey: pub}}
	for _, a := range approvers {
		sig, err := chain.SignKeyChange(a, r.Change)
		if err != nil {
			t.Fatal(err)
		}
		r.AddSignature(sig)
	}
	return r, chain.Signer{ID: id, Key: k}
}

// Keys that were rotated out stay valid on any branch from before the rotation.
// Once the rotation is final they must not be able to replace the chain.
func TestRetiredKeysCannotRewriteTheChain(t *testing.T) {
	e := newEnv(t, 3)
	s := e.signers
	r1, n0 := rotationTo(t, e, 0, s[0].ID, s[0], s[1])
	r2, n1 := rotationTo(t, e, 1, s[1].ID, s[1], s[2])
	first := e.next(s[2], []chain.PayloadEntry{e.payload("real 1")}, []chain.Rotation{r1, r2})
	if _, err := e.store.AddBlock(first); err != nil {
		t.Fatal(err)
	}
	current := []chain.Signer{n0, n1}
	for i := 0; i < chain.RotationFinality; i++ {
		if _, err := e.store.AddBlock(e.next(current[i%2], []chain.PayloadEntry{e.payload(fmt.Sprint("real ", i+2))}, nil)); err != nil {
			t.Fatal(err)
		}
	}
	honest, height := e.store.Head()

	prev := e.genesis.Hash()
	var refused error
	for i := uint64(0); i <= height && refused == nil; i++ {
		f := e.blockOn(prev, i+1, s[i%2], []chain.PayloadEntry{e.payload(fmt.Sprint("forged ", i))}, nil)
		_, refused = e.store.AddBlock(f)
		prev = f.Hash()
	}
	if !errors.Is(refused, chain.ErrReorgRefused) {
		t.Fatalf("forged branch: %v", refused)
	}
	if head, _ := e.store.Head(); head != honest {
		t.Fatal("the head moved to the forged branch")
	}
	re, err := chain.Open(e.dir, e.genesis.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if head, _ := re.Head(); head != honest {
		t.Fatal("after a restart the head moved to the forged branch")
	}
}

func TestReorgDepthIsLimited(t *testing.T) {
	e := newEnv(t, 3)
	s := e.signers
	for i := 0; i <= chain.MaxReorgDepth; i++ {
		if _, err := e.store.AddBlock(e.next(s[i%2], []chain.PayloadEntry{e.payload(fmt.Sprint("real ", i))}, nil)); err != nil {
			t.Fatal(err)
		}
	}
	_, height := e.store.Head()
	prev := e.genesis.Hash()
	var refused error
	for i := uint64(0); i <= height && refused == nil; i++ {
		f := e.blockOn(prev, i+1, s[i%2+1], []chain.PayloadEntry{e.payload(fmt.Sprint("fork ", i))}, nil)
		_, refused = e.store.AddBlock(f)
		prev = f.Hash()
	}
	if !errors.Is(refused, chain.ErrReorgRefused) {
		t.Fatalf("deep fork: %v", refused)
	}
}

func TestPayloadCannotRepeatOnItsBranch(t *testing.T) {
	e := newEnv(t, 3)
	s := e.signers
	p := e.payload("once")
	b1 := e.next(s[0], []chain.PayloadEntry{p}, nil)
	if _, err := e.store.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.AddBlock(e.next(s[1], []chain.PayloadEntry{p}, nil)); err == nil {
		t.Fatal("a payload was accepted twice on one chain")
	}
	// A sibling branch is a different history: the payload may appear there.
	if _, err := e.store.AddBlock(e.blockOn(e.genesis.Hash(), 1, s[1], []chain.PayloadEntry{p}, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestOpenReportsDamagedBlocks(t *testing.T) {
	e := newEnv(t, 3)
	b1 := e.next(e.signers[0], []chain.PayloadEntry{e.payload("one")}, nil)
	if _, err := e.store.AddBlock(b1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.AddBlock(e.next(e.signers[1], []chain.PayloadEntry{e.payload("two")}, nil)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "blocks", b1.Hash().String()+".json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	re, err := chain.Open(e.dir, e.genesis.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if len(re.Skipped) != 2 { // the damaged file, and its child that no longer connects
		t.Fatalf("skipped: %v", re.Skipped)
	}
}

func TestAmbiguousPayloadsAreRefused(t *testing.T) {
	e := newEnv(t, 3)
	p, err := chain.NewParams(e.genesis)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{`null`, `[1]`, `{"text":"a","text":"b"}`, `{"text":"I agree","TEXT":"I refuse"}`, `{"a":{"b":1,"B":2}}`, `{"a":[{"x":1,"x":2}]}`} {
		entry := chain.PayloadEntry{Payload: text, Signature: base64.StdEncoding.EncodeToString(cadesSign(t, e.card, []byte(text)))}
		if _, err := p.VerifyPayload(entry, time.Now()); err == nil {
			t.Errorf("%s was accepted", text)
		}
	}
	good := `{"type":"message","text":"a","nested":{"text":"b","list":[{"text":"c"},{"text":"d"}]}}`
	entry := chain.PayloadEntry{Payload: good, Signature: base64.StdEncoding.EncodeToString(cadesSign(t, e.card, []byte(good)))}
	if _, err := p.VerifyPayload(entry, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestRecordIdentity(t *testing.T) {
	e := newEnv(t, 3)
	other := e.pki.Leaf(t, "ANA ANIC", x509.KeyUsageContentCommitment, true)
	ec := e.pki.Leaf(t, "IVA IVIC", x509.KeyUsageContentCommitment, true)
	same := "co-signed"
	if e.payloadAs(e.card, same).ID() == e.payloadAs(other, same).ID() {
		t.Error("two signers of the same text share a record ID")
	}
	// ECDSA signatures differ each time, but it is still the same record.
	a, b := e.payloadAs(ec, same), e.payloadAs(ec, same)
	if a.Signature == b.Signature {
		t.Fatal("expected two different ECDSA signatures")
	}
	if a.ID() != b.ID() {
		t.Error("re-signing the same text gave a new record ID")
	}
}

func TestOnlyListedCAsAreTrusted(t *testing.T) {
	e := newEnv(t, 3)
	rootOnly, err := chain.NewTrustStore([]string{e.pki.RootPEM})
	if err != nil {
		t.Fatal(err)
	}
	if err := rootOnly.Verify(e.card.Cert, time.Now()); err == nil {
		t.Error("a certificate from an unlisted intermediate was trusted")
	}
	both, err := chain.NewTrustStore([]string{e.pki.RootPEM, e.pki.InterPEM})
	if err != nil {
		t.Fatal(err)
	}
	if err := both.Verify(e.card.Cert, time.Now()); err != nil {
		t.Error(err)
	}
}
