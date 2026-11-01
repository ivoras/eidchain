package chain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// KeyUsageNames lists a certificate's key usage bits.
func KeyUsageNames(c *x509.Certificate) []string {
	names := []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "nonRepudiation"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"},
	}
	var out []string
	for _, n := range names {
		if c.KeyUsage&n.bit != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func extKeyUsageNames(c *x509.Certificate) []string {
	m := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
		x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
		x509.ExtKeyUsageTimeStamping: "timeStamping", x509.ExtKeyUsageOCSPSigning: "ocspSigning",
	}
	var out []string
	for _, u := range c.ExtKeyUsage {
		if n, ok := m[u]; ok {
			out = append(out, n)
		} else {
			out = append(out, fmt.Sprint(u))
		}
	}
	for _, o := range c.UnknownExtKeyUsage {
		out = append(out, o.String())
	}
	return out
}

// DescribeCert renders the certificate fields that matter when debugging trust.
func DescribeCert(c *x509.Certificate) string {
	keyInfo := fmt.Sprintf("%T", c.PublicKey)
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		keyInfo = fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		keyInfo = "ECDSA-" + k.Curve.Params().Name
	}
	return fmt.Sprintf("subject=%q issuer=%q serial=%s valid=%s..%s sigAlg=%s key=%s keyUsage=%v extKeyUsage=%v isCA=%v aki=%x ski=%x ocsp=%v issuerCertURL=%v crl=%v unhandledCriticalExt=%v",
		c.Subject.String(), c.Issuer.String(), c.SerialNumber.Text(16),
		c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339),
		c.SignatureAlgorithm, keyInfo, KeyUsageNames(c), extKeyUsageNames(c), c.IsCA, c.AuthorityKeyId, c.SubjectKeyId,
		c.OCSPServer, c.IssuingCertificateURL, c.CRLDistributionPoints, c.UnhandledCriticalExtensions)
}

// EmbeddedCertificates extracts the certificates from a CMS signature without
// verifying anything, so a rejected signature can still be inspected.
func EmbeddedCertificates(sig []byte) ([]*x509.Certificate, error) {
	ci, _, err := tlv(sig)
	if err != nil {
		return nil, err
	}
	ck, err := kids(ci)
	if err != nil || len(ck) != 2 {
		return nil, fmt.Errorf("not a CMS ContentInfo")
	}
	sd, _, err := tlv(ck[1].Bytes)
	if err != nil {
		return nil, err
	}
	sk, err := kids(sd)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for i := 3; i < len(sk) && sk[i].Class == asn1.ClassContextSpecific; i++ {
		if sk[i].Tag != 0 {
			continue
		}
		cs, err := kids(sk[i])
		if err != nil {
			return certs, err
		}
		for _, c := range cs {
			if cert, err := x509.ParseCertificate(c.FullBytes); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}

// Explain describes how a certificate relates to each trust anchor: whether the
// anchor is a candidate issuer (by name or authority key id) and whether the
// issuer's signature checks out. This pinpoints "unknown authority" failures.
func (t *TrustStore) Explain(c *x509.Certificate, extra []*x509.Certificate) []string {
	var out []string
	found := false
	for _, a := range t.all {
		nameMatch := bytes.Equal(a.RawSubject, c.RawIssuer)
		keyMatch := len(c.AuthorityKeyId) > 0 && bytes.Equal(a.SubjectKeyId, c.AuthorityKeyId)
		if !nameMatch && !keyMatch {
			out = append(out, fmt.Sprintf("trust anchor %q ski=%x: not this certificate's issuer (issuer name match=false, authority key id match=false)", CertName(a), a.SubjectKeyId))
			continue
		}
		found = true
		res := "ok"
		if err := c.CheckSignatureFrom(a); err != nil {
			res = err.Error()
		}
		out = append(out, fmt.Sprintf("trust anchor %q ski=%x: candidate issuer (issuer name match=%v, authority key id match=%v); signature check: %s", CertName(a), a.SubjectKeyId, nameMatch, keyMatch, res))
	}
	if !found {
		out = append(out, "no trust anchor matches the certificate's issuer name or authority key id: its issuing CA is not in the genesis")
	}
	for i, e := range extra {
		if e.Equal(c) {
			continue
		}
		rel := "unrelated"
		if bytes.Equal(e.RawSubject, c.RawIssuer) || (len(c.AuthorityKeyId) > 0 && bytes.Equal(e.SubjectKeyId, c.AuthorityKeyId)) {
			rel = "embedded issuer candidate"
		}
		out = append(out, fmt.Sprintf("embedded cert[%d] (%s): %s", i, rel, DescribeCert(e)))
	}
	if err := t.Verify(c, extra, time.Now()); err != nil {
		out = append(out, "path verification now: "+err.Error())
	} else {
		out = append(out, "path verification now: ok")
	}
	return out
}

// DiagnosePayload explains, in log-ready lines, why e would or would not be
// accepted. It never returns secrets: no signature bytes, and no payload text.
func (p *Params) DiagnosePayload(e PayloadEntry) []string {
	var out []string
	out = append(out, fmt.Sprintf("payload id=%s bytes=%d signatureBase64Bytes=%d ocspBase64Bytes=%d", e.ID().Short(), len(e.Payload), len(e.Signature), len(e.OCSP)))
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return append(out, "signature is not valid base64")
	}
	certs, cerr := EmbeddedCertificates(sig)
	if cerr != nil {
		out = append(out, "could not read embedded certificates: "+cerr.Error())
	}
	var leaf *x509.Certificate
	if s, verr := VerifyDetached(sig, []byte(e.Payload)); verr != nil {
		out = append(out, "CAdES verification failed: "+verr.Error())
		if len(certs) > 0 {
			leaf = certs[0]
		}
	} else {
		out = append(out, fmt.Sprintf("CAdES verification ok: hash=%s claimedSigningTime=%s", s.HashFunction, s.SigningTime.UTC().Format(time.RFC3339)))
		leaf = s.Cert
	}
	if leaf == nil {
		return append(out, fmt.Sprintf("no signer certificate found (%d embedded)", len(certs)))
	}
	out = append(out, "signer certificate: "+DescribeCert(leaf))
	out = append(out, p.Trust.Explain(leaf, certs)...)
	if now := time.Now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		out = append(out, "signer certificate is outside its validity period right now")
	}
	if p.Rules.RequireNonRepudiation && leaf.KeyUsage&x509.KeyUsageContentCommitment == 0 {
		out = append(out, "signer certificate lacks the non-repudiation key usage required by the genesis (likely the authentication certificate)")
	}
	return out
}

// Join is a small helper for log lines.
func Join(parts []string) string { return strings.Join(parts, "; ") }

// SubjectName is the signer's display name: the certificate's common name. Lists
// show only this, not the personal ID number that sits in the subject's serialNumber.
func SubjectName(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	return c.Subject.String()
}

var subjectLabels = map[string]string{
	"2.5.4.3": "CN", "2.5.4.4": "surname", "2.5.4.42": "givenName", "2.5.4.5": "serialNumber",
	"2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.97": "organizationIdentifier",
}

// SubjectDetail renders every subject attribute with a readable label, in place
// of the raw OID hex that x509's own String() produces for the less common ones.
func SubjectDetail(c *x509.Certificate) string {
	var parts []string
	for _, n := range c.Subject.Names {
		label := subjectLabels[n.Type.String()]
		if label == "" {
			label = n.Type.String()
		}
		parts = append(parts, fmt.Sprintf("%s=%v", label, n.Value))
	}
	if len(parts) == 0 {
		return c.Subject.String()
	}
	return strings.Join(parts, ", ")
}
