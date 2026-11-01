// Package tsa gets and verifies RFC 3161 timestamps on block hashes. A timestamp
// is outside evidence that a block existed at a given time: the time comes from
// the authority, not from the node, so it cannot be backdated by the chain's own
// keys. Tokens sign the block hash, so they can only be made after it exists and
// are kept beside the block, not in it. Block validity never depends on them, and
// an outage at an authority cannot stop the chain.
package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1" // the ESSCertID hash, which RFC 3161 tokens still use
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

//go:embed roots/*.pem
var rootFiles embed.FS

// Authority is a timestamp service.
type Authority struct {
	Root string        // common name of the root its tokens chain to
	URL  string        // RFC 3161 HTTP endpoint
	Gap  time.Duration // wait between requests
}

// Default lists the authorities used by a node that signs blocks. Neither issues
// qualified eIDAS timestamps. Both are free: Sectigo asks scripts to wait at least
// 15 seconds between requests.
var Default = []Authority{
	{Root: "Sectigo Public Time Stamping Root R46", URL: "http://timestamp.sectigo.com", Gap: 15 * time.Second},
	{Root: "www.freetsa.org", URL: "https://freetsa.org/tsr", Gap: 15 * time.Second},
}

// Roots returns the embedded roots of the default authorities.
func Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	files, err := rootFiles.ReadDir("roots")
	if err != nil {
		panic(err)
	}
	for _, f := range files {
		raw, err := rootFiles.ReadFile("roots/" + f.Name())
		if err != nil {
			panic(err)
		}
		if !pool.AppendCertsFromPEM(raw) {
			panic("tsa: bad embedded root " + f.Name())
		}
	}
	return pool
}

// MaxToken bounds a token, whether from an authority or a peer.
const MaxToken = 32 << 10

// maxRSABits bounds the work one token can demand.
const maxRSABits = 8192

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

	hashByOID = map[string]crypto.Hash{
		"2.16.840.1.101.3.4.2.1": crypto.SHA256,
		"2.16.840.1.101.3.4.2.2": crypto.SHA384,
		"2.16.840.1.101.3.4.2.3": crypto.SHA512,
	}
)

// Info is what a verified token says.
type Info struct {
	Time      time.Time // when the authority saw the hash
	Authority string    // common name of the root the token chains to
	Signer    string    // common name of the signing certificate
	nonce     *big.Int
}

type messageImprint struct {
	Alg  pkix.AlgorithmIdentifier
	Hash []byte
}

type timeStampReq struct {
	Version int
	Imprint messageImprint
	Nonce   *big.Int
	CertReq bool
}

// Request asks an authority to timestamp hash and returns its verified token.
func Request(ctx context.Context, client *http.Client, url string, hash [32]byte, roots *x509.CertPool) ([]byte, Info, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, Info{}, err
	}
	nonce.Add(nonce, big.NewInt(1)) // never zero
	body, err := asn1.Marshal(timeStampReq{
		Version: 1,
		Imprint: messageImprint{pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, hash[:]},
		Nonce:   nonce, CertReq: true,
	})
	if err != nil {
		return nil, Info{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, Info{}, err
	}
	req.Header.Set("Content-Type", "application/timestamp-query")
	resp, err := client.Do(req)
	if err != nil {
		return nil, Info{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxToken+1024))
	if err != nil {
		return nil, Info{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, Info{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	token, err := parseResponse(raw)
	if err != nil {
		return nil, Info{}, err
	}
	info, err := Verify(token, hash, roots)
	if err != nil {
		return nil, Info{}, err
	}
	if info.nonce == nil || info.nonce.Cmp(nonce) != 0 {
		return nil, Info{}, errors.New("token does not carry our nonce")
	}
	return token, info, nil
}

// parseResponse returns the token in a TimeStampResp, if it was granted.
func parseResponse(raw []byte) ([]byte, error) {
	top, rest, err := tlv(raw)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("response is not a single DER value")
	}
	k, err := kids(top)
	if err != nil || len(k) == 0 {
		return nil, errors.New("malformed TimeStampResp")
	}
	st, err := kids(k[0])
	if err != nil || len(st) == 0 {
		return nil, errors.New("malformed PKIStatusInfo")
	}
	var status int
	if _, err := asn1.Unmarshal(st[0].FullBytes, &status); err != nil {
		return nil, errors.New("malformed PKIStatus")
	}
	if status != 0 && status != 1 { // granted, grantedWithMods
		return nil, fmt.Errorf("the authority refused the request (status %d)", status)
	}
	if len(k) < 2 {
		return nil, errors.New("granted, but no token in the response")
	}
	return k[1].FullBytes, nil
}

// Verify checks that token is a timestamp on exactly hash, signed by a certificate
// that chains to roots and was valid at the time the token states. Certificates
// are judged at that time, so a token outlives its signer. Revocation is not
// checked.
func Verify(token []byte, hash [32]byte, roots *x509.CertPool) (Info, error) {
	if len(token) == 0 || len(token) > MaxToken {
		return Info{}, errors.New("token is empty or too large")
	}
	ci, rest, err := tlv(token)
	if err != nil || len(rest) != 0 {
		return Info{}, errors.New("token is not a single DER value")
	}
	ck, err := kids(ci)
	if err != nil || len(ck) != 2 || ck[1].Class != asn1.ClassContextSpecific || ck[1].Tag != 0 {
		return Info{}, errors.New("malformed ContentInfo")
	}
	if o, err := oidOf(ck[0]); err != nil || !o.Equal(oidSignedData) {
		return Info{}, errors.New("not a CMS SignedData")
	}
	sd, _, err := tlv(ck[1].Bytes)
	if err != nil {
		return Info{}, err
	}
	sk, err := kids(sd)
	if err != nil || len(sk) < 4 {
		return Info{}, errors.New("malformed SignedData")
	}
	tst, err := encapsulated(sk[2])
	if err != nil {
		return Info{}, err
	}
	info, err := parseTSTInfo(tst, hash)
	if err != nil {
		return Info{}, err
	}

	i := 3
	var certs []*x509.Certificate
	for ; i < len(sk) && sk[i].Class == asn1.ClassContextSpecific; i++ {
		if sk[i].Tag != 0 {
			continue
		}
		cs, err := kids(sk[i])
		if err != nil {
			return Info{}, err
		}
		for _, c := range cs {
			cert, err := x509.ParseCertificate(c.FullBytes)
			if err != nil {
				return Info{}, fmt.Errorf("embedded certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	if i >= len(sk) {
		return Info{}, errors.New("missing signerInfos")
	}
	sis, err := kids(sk[i])
	if err != nil || len(sis) != 1 {
		return Info{}, errors.New("exactly one signer is required")
	}
	si, err := kids(sis[0])
	if err != nil || len(si) < 6 {
		return Info{}, errors.New("malformed SignerInfo")
	}
	signer, err := findSigner(si[1], certs)
	if err != nil {
		return Info{}, err
	}

	// Trust comes before any public-key work: a key nobody trusts costs nothing.
	inter := x509.NewCertPool()
	for _, c := range certs {
		inter.AddCert(c)
	}
	chains, err := signer.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: info.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return Info{}, fmt.Errorf("signer not trusted: %w", err)
	}
	chain := chains[0]
	info.Authority = chain[len(chain)-1].Subject.CommonName
	info.Signer = signer.Subject.CommonName

	hashFn, err := algHash(si[2])
	if err != nil {
		return Info{}, err
	}
	if si[3].Class != asn1.ClassContextSpecific || si[3].Tag != 0 {
		return Info{}, errors.New("signed attributes are required")
	}
	if err := checkAttributes(si[3], hashFn, tst, signer); err != nil {
		return Info{}, err
	}
	sigAlg, err := kids(si[4])
	if err != nil || len(sigAlg) == 0 {
		return Info{}, errors.New("bad signature algorithm")
	}
	if o, _ := oidOf(sigAlg[0]); o.Equal(oidRSAPSS) {
		return Info{}, errors.New("RSA-PSS is not supported")
	}
	if si[5].Class != asn1.ClassUniversal || si[5].Tag != asn1.TagOctetString {
		return Info{}, errors.New("bad signature value")
	}
	// The signature covers the attributes with a SET tag.
	toSign := append([]byte{}, si[3].FullBytes...)
	toSign[0] = 0x31
	h := hashFn.New()
	h.Write(toSign)
	digest := h.Sum(nil)
	switch pub := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() > maxRSABits {
			return Info{}, errors.New("RSA key is too large")
		}
		if err := rsa.VerifyPKCS1v15(pub, hashFn, digest, si[5].Bytes); err != nil {
			return Info{}, errors.New("RSA signature invalid")
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, si[5].Bytes) {
			return Info{}, errors.New("ECDSA signature invalid")
		}
	default:
		return Info{}, errors.New("unsupported signer key type")
	}
	return info, nil
}

// encapsulated returns the TSTInfo bytes from an EncapsulatedContentInfo.
func encapsulated(rv asn1.RawValue) ([]byte, error) {
	k, err := kids(rv)
	if err != nil || len(k) != 2 || k[1].Tag != 0 {
		return nil, errors.New("malformed encapsulated content")
	}
	if o, err := oidOf(k[0]); err != nil || !o.Equal(oidTSTInfo) {
		return nil, errors.New("the content is not a TSTInfo")
	}
	oct, _, err := tlv(k[1].Bytes)
	if err != nil || oct.Class != asn1.ClassUniversal || oct.Tag != asn1.TagOctetString {
		return nil, errors.New("malformed encapsulated content")
	}
	return oct.Bytes, nil
}

func parseTSTInfo(raw []byte, hash [32]byte) (Info, error) {
	top, rest, err := tlv(raw)
	if err != nil || len(rest) != 0 {
		return Info{}, errors.New("malformed TSTInfo")
	}
	k, err := kids(top)
	if err != nil || len(k) < 5 {
		return Info{}, errors.New("malformed TSTInfo")
	}
	var imprint messageImprint
	if _, err := asn1.Unmarshal(k[2].FullBytes, &imprint); err != nil {
		return Info{}, errors.New("malformed messageImprint")
	}
	if !imprint.Alg.Algorithm.Equal(oidSHA256) || !bytes.Equal(imprint.Hash, hash[:]) {
		return Info{}, errors.New("the token is for a different hash")
	}
	var info Info
	if _, err := asn1.Unmarshal(k[4].FullBytes, &info.Time); err != nil {
		return Info{}, errors.New("malformed genTime")
	}
	for _, f := range k[5:] { // accuracy and ordering may come first
		if f.Class == asn1.ClassUniversal && f.Tag == asn1.TagInteger {
			info.nonce = new(big.Int)
			if _, err := asn1.Unmarshal(f.FullBytes, &info.nonce); err != nil {
				return Info{}, errors.New("malformed nonce")
			}
		}
	}
	return info, nil
}

// checkAttributes requires the content type and the digest of the TSTInfo, and the
// ESS attribute that names the signing certificate, each exactly once.
func checkAttributes(attrs asn1.RawValue, hashFn crypto.Hash, content []byte, signer *x509.Certificate) error {
	list, err := kids(attrs)
	if err != nil {
		return err
	}
	h := hashFn.New()
	h.Write(content)
	want := h.Sum(nil)
	typeOK, digestOK, signerOK := false, false, false
	seen := map[string]bool{}
	for _, a := range list {
		ak, err := kids(a)
		if err != nil || len(ak) != 2 {
			return errors.New("malformed attribute")
		}
		o, err := oidOf(ak[0])
		if err != nil {
			return err
		}
		if seen[o.String()] {
			return fmt.Errorf("duplicate attribute %s", o)
		}
		seen[o.String()] = true
		vals, err := kids(ak[1])
		if err != nil || len(vals) != 1 {
			return fmt.Errorf("attribute %s must have one value", o)
		}
		switch {
		case o.Equal(oidContentType):
			ct, err := oidOf(vals[0])
			typeOK = err == nil && ct.Equal(oidTSTInfo)
		case o.Equal(oidMessageDigest):
			digestOK = bytes.Equal(vals[0].Bytes, want)
		case o.Equal(oidSigningCert), o.Equal(oidSigningCertV2):
			if signerOK {
				return errors.New("more than one signing-certificate attribute")
			}
			if err := checkSigningCert(vals[0], o.Equal(oidSigningCertV2), signer); err != nil {
				return err
			}
			signerOK = true
		}
	}
	if !typeOK {
		return errors.New("content-type attribute missing or wrong")
	}
	if !digestOK {
		return errors.New("message digest does not match the TSTInfo")
	}
	if !signerOK {
		return errors.New("signing-certificate attribute missing")
	}
	return nil
}

// checkSigningCert requires the first ESSCertID to name the signer (RFC 2634 5.4,
// RFC 5035): SHA-1 in the original attribute, SHA-256 by default in the V2 one.
func checkSigningCert(v asn1.RawValue, v2 bool, signer *x509.Certificate) error {
	top, err := kids(v)
	if err != nil || len(top) == 0 {
		return errors.New("bad signing-certificate attribute")
	}
	ids, err := kids(top[0])
	if err != nil || len(ids) == 0 {
		return errors.New("bad signing-certificate attribute")
	}
	id, err := kids(ids[0])
	if err != nil || len(id) == 0 {
		return errors.New("bad ESSCertID")
	}
	hashFn := crypto.SHA1
	if v2 {
		hashFn = crypto.SHA256
		if id[0].Class == asn1.ClassUniversal && id[0].Tag == asn1.TagSequence {
			if hashFn, err = algHash(id[0]); err != nil {
				return err
			}
			id = id[1:]
		}
	}
	if len(id) == 0 || id[0].Tag != asn1.TagOctetString {
		return errors.New("bad ESSCertID hash")
	}
	h := hashFn.New()
	h.Write(signer.Raw)
	if !bytes.Equal(h.Sum(nil), id[0].Bytes) {
		return errors.New("the signing-certificate attribute names a different certificate")
	}
	return nil
}

func findSigner(sid asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
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
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
	}
	return nil, errors.New("signer certificate is not in the token")
}

func tlv(b []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	return rv, rest, err
}

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

func oidOf(rv asn1.RawValue) (asn1.ObjectIdentifier, error) {
	var o asn1.ObjectIdentifier
	_, err := asn1.Unmarshal(rv.FullBytes, &o)
	return o, err
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
