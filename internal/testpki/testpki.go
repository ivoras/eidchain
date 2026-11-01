// Package testpki builds throwaway certificate hierarchies and CAdES-B-B
// signatures for tests. Never import it from non-test code.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sort"
	"testing"
	"time"
)

type PKI struct {
	RootPEM, InterPEM string
	interCert         *x509.Certificate
	interKey          *ecdsa.PrivateKey
}

func New(t testing.TB) *PKI {
	t.Helper()
	mk := func(cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
			NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(240 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		if parent == nil {
			parent, parentKey = tpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c, key, der
	}
	root, rootKey, rootDER := mk("Test Root", nil, nil)
	inter, interKey, interDER := mk("Test HRIDCA", root, rootKey)
	enc := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return &PKI{RootPEM: enc(rootDER), InterPEM: enc(interDER), interCert: inter, interKey: interKey}
}

type Leaf struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func (p *PKI) Leaf(t testing.TB, cn string, usage x509.KeyUsage, useEC bool) Leaf {
	t.Helper()
	var key crypto.Signer
	if useEC {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	} else {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.interCert, key.Public(), p.interKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return Leaf{c, key}
}

// CadesSign builds a detached CAdES-B-B signature, mirroring www/signer/cades.js.
func enc(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	n := len(body)
	hdr := []byte{tag}
	switch {
	case n < 128:
		hdr = append(hdr, byte(n))
	case n < 256:
		hdr = append(hdr, 0x81, byte(n))
	default:
		hdr = append(hdr, 0x82, byte(n>>8), byte(n))
	}
	return append(hdr, body...)
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func CadesSign(t testing.TB, l Leaf, content []byte) []byte {
	t.Helper()
	oid := func(o ...int) []byte { return mustMarshal(asn1.ObjectIdentifier(o)) }
	attr := func(o []byte, val []byte) []byte { return enc(0x30, o, enc(0x31, val)) }
	digest := sha256.Sum256(content)
	certHash := sha256.Sum256(l.Cert.Raw)
	issuerSerial := enc(0x30, enc(0x30, enc(0xa4, l.Cert.RawIssuer)), mustMarshal(l.Cert.SerialNumber))
	ess := enc(0x30, enc(0x30, enc(0x30, enc(0x04, certHash[:]), issuerSerial)))
	attrs := [][]byte{
		attr(oid(1, 2, 840, 113549, 1, 9, 3), oid(1, 2, 840, 113549, 1, 7, 1)),
		attr(oid(1, 2, 840, 113549, 1, 9, 4), enc(0x04, digest[:])),
		attr(oid(1, 2, 840, 113549, 1, 9, 5), mustMarshal(time.Now().UTC().Truncate(time.Second))),
		attr(oid(1, 2, 840, 113549, 1, 9, 16, 2, 47), ess),
	}
	sort.Slice(attrs, func(i, j int) bool { return string(attrs[i]) < string(attrs[j]) })
	var all []byte
	for _, a := range attrs {
		all = append(all, a...)
	}
	toSign := enc(0x31, all)
	sum := sha256.Sum256(toSign)
	var sig, sigAlg []byte
	switch k := l.Key.(type) {
	case *rsa.PrivateKey:
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		sigAlg = enc(0x30, oid(1, 2, 840, 113549, 1, 1, 11), []byte{0x05, 0x00})
	case *ecdsa.PrivateKey:
		sig, _ = ecdsa.SignASN1(rand.Reader, k, sum[:])
		sigAlg = enc(0x30, oid(1, 2, 840, 10045, 4, 3, 2))
	}
	digestAlg := enc(0x30, oid(2, 16, 840, 1, 101, 3, 4, 2, 1))
	si := enc(0x30, []byte{2, 1, 1}, enc(0x30, l.Cert.RawIssuer, mustMarshal(l.Cert.SerialNumber)),
		digestAlg, enc(0xa0, all), sigAlg, enc(0x04, sig))
	sd := enc(0x30, []byte{2, 1, 1}, enc(0x31, digestAlg), enc(0x30, oid(1, 2, 840, 113549, 1, 7, 1)),
		enc(0xa0, l.Cert.Raw), enc(0x31, si))
	return enc(0x30, oid(1, 2, 840, 113549, 1, 7, 2), enc(0xa0, sd))
}
