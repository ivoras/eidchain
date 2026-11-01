package chain_test

import (
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"eidchain/internal/chain"
	"eidchain/internal/testpki"
)

type (
	pki  = testpki.PKI
	leaf = testpki.Leaf
)

func newPKI(t *testing.T) *pki { return testpki.New(t) }

func cadesSign(t *testing.T, l leaf, content []byte) []byte { return testpki.CadesSign(t, l, content) }

// ---- chain environment ----

type env struct {
	t       *testing.T
	pki     *pki
	dir     string
	store   *chain.Store
	signers []chain.Signer // aligned with the genesis authority order
	genesis *chain.Genesis
	card    leaf // a valid signing certificate
}

func newEnv(t *testing.T, authorities int) *env {
	t.Helper()
	e := &env{t: t, pki: newPKI(t), dir: t.TempDir()}
	var auths []chain.Authority
	for i := 0; i < authorities; i++ {
		k, _ := chain.GenerateKey()
		id, _ := chain.KeyID(&k.PublicKey)
		pub, _ := chain.EncodePublicKey(&k.PublicKey)
		e.signers = append(e.signers, chain.Signer{ID: id, Key: k})
		auths = append(auths, chain.Authority{PublicKey: pub})
	}
	g, err := chain.NewGenesis("test chain", auths, []string{e.pki.RootPEM, e.pki.InterPEM}, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	e.genesis = g
	if e.store, err = chain.Init(e.dir, g); err != nil {
		t.Fatal(err)
	}
	e.card = e.pki.Leaf(t, "PERA PERIC", x509.KeyUsageContentCommitment|x509.KeyUsageDigitalSignature, false)
	return e
}

func (e *env) payload(text string) chain.PayloadEntry { return e.payloadAs(e.card, text) }

func (e *env) payloadAs(l leaf, text string) chain.PayloadEntry {
	p := `{"type":"message","text":"` + text + `"}`
	return chain.PayloadEntry{Payload: p, Signature: base64.StdEncoding.EncodeToString(cadesSign(e.t, l, []byte(p)))}
}

// blockOn builds a signed block on top of the given parent hash.
func (e *env) blockOn(prev chain.Hash, height uint64, s chain.Signer, payloads []chain.PayloadEntry, rots []chain.Rotation) *chain.Block {
	b := &chain.Block{Header: chain.Header{Height: height, Prev: prev, Time: time.Now().Unix()}, Payloads: payloads, Rotations: rots}
	if err := chain.SignBlock(s, b); err != nil {
		e.t.Fatal(err)
	}
	return b
}

func (e *env) next(s chain.Signer, payloads []chain.PayloadEntry, rots []chain.Rotation) *chain.Block {
	head, h := e.store.Head()
	return e.blockOn(head, h+1, s, payloads, rots)
}
