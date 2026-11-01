package chain

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// TrustStore holds the CA certificates from the genesis block. Self-signed
// certificates are roots; the rest are intermediates.
type TrustStore struct {
	roots *x509.CertPool
	inter *x509.CertPool
	all   []*x509.Certificate
}

// NewTrustStore parses PEM-encoded certificates.
func NewTrustStore(pems []string) (*TrustStore, error) {
	t := &TrustStore{roots: x509.NewCertPool(), inter: x509.NewCertPool()}
	nroots := 0
	for i, p := range pems {
		rest := []byte(p)
		found := false
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("trust anchor %d: %w", i, err)
			}
			found = true
			t.all = append(t.all, c)
			if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
				t.roots.AddCert(c)
				nroots++
			} else {
				t.inter.AddCert(c)
			}
		}
		if !found {
			return nil, fmt.Errorf("trust anchor %d: no certificate found", i)
		}
	}
	if nroots == 0 {
		return nil, errors.New("trust anchors contain no self-signed root")
	}
	return t, nil
}

// Verify checks that cert chains to a trusted root through CAs listed in the
// genesis, judged at time at (the block's timestamp, so validation is
// deterministic). Intermediates embedded in a signature are deliberately not used:
// they would admit every CA under a root, not just the ones the genesis names.
func (t *TrustStore) Verify(cert *x509.Certificate, at time.Time) error {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         t.roots,
		Intermediates: t.inter,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// Issuer finds the trust-store certificate that issued cert (needed for OCSP).
func (t *TrustStore) Issuer(cert *x509.Certificate) *x509.Certificate {
	for _, c := range t.all {
		if bytes.Equal(c.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(c) == nil {
			return c
		}
	}
	return nil
}

// Certificates returns every CA certificate in the store (roots and intermediates).
func (t *TrustStore) Certificates() []*x509.Certificate {
	return append([]*x509.Certificate(nil), t.all...)
}

// CertName is a short human-readable name: "CN (O)".
func CertName(c *x509.Certificate) string {
	name := c.Subject.CommonName
	if len(c.Subject.Organization) > 0 {
		name += " (" + c.Subject.Organization[0] + ")"
	}
	if name == "" {
		return c.Subject.String()
	}
	return name
}

// Names lists the trust anchors by short name, for error messages.
func (t *TrustStore) Names() []string {
	var out []string
	for _, c := range t.all {
		out = append(out, CertName(c))
	}
	return out
}

// CertName2 formats a CN and organisations like CertName does for a certificate.
func CertName2(cn string, orgs []string) string {
	if len(orgs) > 0 {
		return cn + " (" + orgs[0] + ")"
	}
	return cn
}
