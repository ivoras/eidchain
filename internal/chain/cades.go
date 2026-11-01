package chain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	hashByOID = map[string]crypto.Hash{
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
)

// Signature is the verified content of a detached CAdES-B-B signature.
type Signature struct {
	Cert         *x509.Certificate
	Certs        []*x509.Certificate // every certificate embedded in the signature
	SigningTime  time.Time           // claimed by the signer; zero if absent. Not trusted.
	HashFunction crypto.Hash
}

// tlv parses one DER element and returns the remainder.
func tlv(b []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	return rv, rest, err
}

// kids returns the elements inside a constructed value.
func kids(rv asn1.RawValue) ([]asn1.RawValue, error) {
	if !rv.IsCompound {
		return nil, errors.New("expected a constructed element")
	}
	var out []asn1.RawValue
	for b := rv.Bytes; len(b) > 0; {
		c, rest, err := tlv(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

func isUniversal(rv asn1.RawValue, tag int) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == tag
}

func isContext(rv asn1.RawValue, tag int) bool {
	return rv.Class == asn1.ClassContextSpecific && rv.Tag == tag
}

func oidOf(rv asn1.RawValue) (asn1.ObjectIdentifier, error) {
	var o asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(rv.FullBytes, &o); err != nil {
		return nil, err
	}
	return o, nil
}

func algHash(rv asn1.RawValue) (crypto.Hash, error) {
	k, err := kids(rv)
	if err != nil || len(k) == 0 {
		return 0, errors.New("bad AlgorithmIdentifier")
	}
	o, err := oidOf(k[0])
	if err != nil {
		return 0, err
	}
	h, ok := hashByOID[o.String()]
	if !ok {
		return 0, fmt.Errorf("unsupported hash algorithm %s", o)
	}
	return h, nil
}

// parseSignedData walks a CMS ContentInfo down to its certificates and its one SignerInfo.
func parseSignedData(sig []byte) ([]*x509.Certificate, []asn1.RawValue, error) {
	ci, rest, err := tlv(sig)
	if err != nil || len(rest) != 0 || !isUniversal(ci, asn1.TagSequence) {
		return nil, nil, errors.New("signature is not a single DER sequence")
	}
	ck, err := kids(ci)
	if err != nil || len(ck) != 2 {
		return nil, nil, errors.New("malformed ContentInfo")
	}
	if o, err := oidOf(ck[0]); err != nil || !o.Equal(oidSignedData) {
		return nil, nil, errors.New("not a CMS SignedData")
	}
	if !isContext(ck[1], 0) {
		return nil, nil, errors.New("malformed ContentInfo content")
	}
	sd, _, err := tlv(ck[1].Bytes)
	if err != nil {
		return nil, nil, err
	}
	sk, err := kids(sd)
	if err != nil || len(sk) < 4 {
		return nil, nil, errors.New("malformed SignedData")
	}
	// sk[0]=version, sk[1]=digestAlgorithms, sk[2]=encapContentInfo
	ek, err := kids(sk[2])
	if err != nil || len(ek) != 1 {
		return nil, nil, errors.New("signature must be detached (no embedded content)")
	}
	i := 3
	var certs []*x509.Certificate
	for ; i < len(sk) && sk[i].Class == asn1.ClassContextSpecific; i++ {
		if sk[i].Tag != 0 {
			continue // CRLs and other choices are ignored
		}
		cs, err := kids(sk[i])
		if err != nil {
			return nil, nil, err
		}
		for _, c := range cs {
			if !isUniversal(c, asn1.TagSequence) {
				continue
			}
			cert, err := x509.ParseCertificate(c.FullBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("embedded certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	if i >= len(sk) || !isUniversal(sk[i], asn1.TagSet) {
		return nil, nil, errors.New("missing signerInfos")
	}
	sis, err := kids(sk[i])
	if err != nil || len(sis) != 1 {
		return nil, nil, errors.New("exactly one signer is required")
	}
	si, err := kids(sis[0])
	if err != nil || len(si) < 5 {
		return nil, nil, errors.New("malformed SignerInfo")
	}
	return certs, si, nil
}

// signerCertHash names who claims to have made sig, without verifying anything:
// the SHA-256 of the signer's certificate. It serves as an identity for records,
// because unlike the signature bytes it cannot be varied by a third party.
func signerCertHash(sig []byte) ([32]byte, error) {
	certs, si, err := parseSignedData(sig)
	if err != nil {
		return [32]byte{}, err
	}
	cert, err := findSigner(si[1], certs)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(cert.Raw), nil
}

// VerifyDetached checks a detached CAdES (CMS SignedData) signature over
// content: structure, the signer's signature over the signed attributes, the
// message digest, and the ESS signing-certificate-v2 binding that CAdES-B-B
// requires. It does not judge the certificate; see TrustStore.Verify.
func VerifyDetached(sig, content []byte) (*Signature, error) {
	certs, si, err := parseSignedData(sig)
	if err != nil {
		return nil, err
	}
	// si[0]=version si[1]=sid si[2]=digestAlg [si[3]=signedAttrs] sigAlg signature
	hashFn, err := algHash(si[2])
	if err != nil {
		return nil, err
	}
	n := 3
	if !isContext(si[n], 0) {
		return nil, errors.New("signed attributes are required")
	}
	attrs := si[n]
	n++
	if n+1 >= len(si) {
		return nil, errors.New("malformed SignerInfo")
	}
	sigAlg, err := kids(si[n])
	if err != nil || len(sigAlg) == 0 {
		return nil, errors.New("bad signature algorithm")
	}
	if o, _ := oidOf(sigAlg[0]); o.Equal(oidRSAPSS) {
		return nil, errors.New("RSA-PSS signatures are not supported")
	}
	if !isUniversal(si[n+1], asn1.TagOctetString) {
		return nil, errors.New("bad signature value")
	}
	sigValue := si[n+1].Bytes

	cert, err := findSigner(si[1], certs)
	if err != nil {
		return nil, err
	}

	// Signed attributes.
	attrList, err := kids(attrs)
	if err != nil {
		return nil, err
	}
	var (
		messageDigest []byte
		ctypeOK       bool
		certHashOK    bool
		signingTime   time.Time
		seen          = map[string]bool{}
	)
	for _, a := range attrList {
		ak, err := kids(a)
		if err != nil || len(ak) != 2 {
			return nil, errors.New("malformed attribute")
		}
		o, err := oidOf(ak[0])
		if err != nil {
			return nil, err
		}
		if seen[o.String()] {
			return nil, fmt.Errorf("duplicate attribute %s", o)
		}
		seen[o.String()] = true
		vals, err := kids(ak[1])
		if err != nil || len(vals) != 1 {
			return nil, fmt.Errorf("attribute %s must have one value", o)
		}
		v := vals[0]
		switch {
		case o.Equal(oidContentType):
			ct, err := oidOf(v)
			ctypeOK = err == nil && ct.Equal(oidData)
		case o.Equal(oidMessageDigest):
			if !isUniversal(v, asn1.TagOctetString) {
				return nil, errors.New("bad messageDigest")
			}
			messageDigest = v.Bytes
		case o.Equal(oidSigningTime):
			if _, err := asn1.Unmarshal(v.FullBytes, &signingTime); err != nil {
				return nil, errors.New("bad signingTime")
			}
		case o.Equal(oidSigningCertV2):
			if err := checkSigningCertV2(v, cert); err != nil {
				return nil, err
			}
			certHashOK = true
		}
	}
	if !ctypeOK {
		return nil, errors.New("content-type attribute missing or not id-data")
	}
	if !certHashOK {
		return nil, errors.New("signing-certificate-v2 attribute missing (not CAdES-B-B)")
	}
	if !hashFn.Available() {
		return nil, errors.New("hash function unavailable")
	}
	h := hashFn.New()
	h.Write(content)
	if !bytes.Equal(h.Sum(nil), messageDigest) {
		return nil, errors.New("message digest does not match the payload")
	}

	// The signature covers the DER of the attributes with a SET tag.
	toSign := append([]byte{}, attrs.FullBytes...)
	toSign[0] = 0x31
	ah := hashFn.New()
	ah.Write(toSign)
	digest := ah.Sum(nil)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, hashFn, digest, sigValue); err != nil {
			return nil, errors.New("RSA signature invalid")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, sigValue) {
			return nil, errors.New("ECDSA signature invalid")
		}
	default:
		return nil, errors.New("unsupported signer key type")
	}
	return &Signature{Cert: cert, Certs: certs, SigningTime: signingTime, HashFunction: hashFn}, nil
}

// findSigner resolves the SignerIdentifier to one of the embedded certificates.
func findSigner(sid asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case isUniversal(sid, asn1.TagSequence): // IssuerAndSerialNumber
		k, err := kids(sid)
		if err != nil || len(k) != 2 {
			return nil, errors.New("bad IssuerAndSerialNumber")
		}
		serial := new(big.Int)
		if _, err := asn1.Unmarshal(k[1].FullBytes, &serial); err != nil {
			return nil, err
		}
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, k[0].FullBytes) && c.SerialNumber.Cmp(serial) == 0 {
				return c, nil
			}
		}
	case isContext(sid, 0): // SubjectKeyIdentifier
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
	}
	return nil, errors.New("signer certificate is not embedded in the signature")
}

// checkSigningCertV2 verifies the ESSCertIDv2 hash binds the signature to cert.
func checkSigningCertV2(v asn1.RawValue, cert *x509.Certificate) error {
	top, err := kids(v) // SigningCertificateV2 ::= SEQUENCE { certs SEQUENCE OF ESSCertIDv2, ... }
	if err != nil || len(top) == 0 {
		return errors.New("bad signing-certificate-v2")
	}
	ids, err := kids(top[0])
	if err != nil || len(ids) == 0 {
		return errors.New("bad signing-certificate-v2")
	}
	idk, err := kids(ids[0])
	if err != nil || len(idk) == 0 {
		return errors.New("bad ESSCertIDv2")
	}
	hashFn := crypto.SHA256 // DEFAULT when hashAlgorithm is omitted
	if isUniversal(idk[0], asn1.TagSequence) {
		if hashFn, err = algHash(idk[0]); err != nil {
			return err
		}
		idk = idk[1:]
	}
	if len(idk) == 0 || !isUniversal(idk[0], asn1.TagOctetString) {
		return errors.New("bad ESSCertIDv2 hash")
	}
	h := hashFn.New()
	h.Write(cert.Raw)
	if !bytes.Equal(h.Sum(nil), idk[0].Bytes) {
		return errors.New("signing certificate does not match signing-certificate-v2")
	}
	return nil
}
