package chain_test

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"eidchain/internal/chain"
	"golang.org/x/crypto/ocsp"
)

func ocspResponse(t *testing.T, e *env, responder leaf, thisUpdate, nextUpdate time.Time) ([]byte, *x509.Certificate) {
	t.Helper()
	blk, _ := pem.Decode([]byte(e.pki.InterPEM))
	issuer, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ocsp.CreateResponse(issuer, e.card.Cert, ocsp.Response{
		Status: ocsp.Good, SerialNumber: e.card.Cert.SerialNumber,
		ThisUpdate: thisUpdate, NextUpdate: nextUpdate, Certificate: responder.Cert,
	}, responder.Key.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	return raw, issuer
}

// A cardholder must not be able to vouch for their own, possibly revoked, card:
// their certificate is signed by the right CA but is not an OCSP responder.
func TestOCSPRefusesResponderWithoutEKU(t *testing.T) {
	e := newEnv(t, 3)
	now := time.Now()
	raw, issuer := ocspResponse(t, e, e.card, now.Add(-time.Minute), now.Add(time.Hour))
	if err := chain.VerifyOCSP(raw, e.card.Cert, issuer, now); err == nil || !strings.Contains(err.Error(), "not authorised") {
		t.Fatalf("self-signed OCSP response: %v", err)
	}
}

func TestOCSPAcceptsDelegatedResponderAndBoundsAge(t *testing.T) {
	e := newEnv(t, 3)
	responder := e.pki.OCSPResponder(t)
	now := time.Now()
	raw, issuer := ocspResponse(t, e, responder, now.Add(-time.Minute), now.Add(30*24*time.Hour))
	if err := chain.VerifyOCSP(raw, e.card.Cert, issuer, now); err != nil {
		t.Fatalf("delegated responder: %v", err)
	}
	if err := chain.VerifyOCSP(raw, e.card.Cert, issuer, now.Add(7*24*time.Hour)); err == nil {
		t.Fatal("a week-old response was accepted because of its long nextUpdate")
	}
}
