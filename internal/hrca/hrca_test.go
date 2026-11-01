package hrca

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// The bundle must hold the root and both intermediates, each properly issued:
// HRIDCA (cards before May 2025) and HRIDCA 2025 (newer AKD eID 2.0 cards).
func TestBundleChains(t *testing.T) {
	var certs []*x509.Certificate
	for rest := []byte(PEM); ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, c)
	}
	names := map[string]*x509.Certificate{}
	for _, c := range certs {
		names[c.Subject.CommonName] = c
	}
	root := names["AKDCA Root"]
	if len(certs) != 3 || root == nil || names["HRIDCA"] == nil || names["HRIDCA 2025"] == nil {
		t.Fatalf("unexpected bundle: %d certs, %v", len(certs), names)
	}
	for _, n := range []string{"HRIDCA", "HRIDCA 2025"} {
		if err := names[n].CheckSignatureFrom(root); err != nil {
			t.Errorf("%s is not issued by AKDCA Root: %v", n, err)
		}
	}
	if string(names["HRIDCA 2025"].SubjectKeyId[:2]) != "\xf1\xa7" {
		t.Error("HRIDCA 2025 key id changed")
	}
	if p, ok := Builtin("hr"); !ok || p != PEM {
		t.Error("builtin hr missing")
	}
}
