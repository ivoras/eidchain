package chain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Signer is an authority private key held by a node.
type Signer struct {
	ID  string
	Key *ecdsa.PrivateKey
}

// GenerateKey creates a new ECDSA P-256 authority key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// KeyID is the hex SHA-256 of the DER SubjectPublicKeyInfo.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// EncodePublicKey returns base64(DER SPKI), the form used in genesis files.
func EncodePublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// DecodePublicKey parses base64(DER SPKI) or a PEM "PUBLIC KEY" block and
// requires an ECDSA P-256 key.
func DecodePublicKey(s string) (*ecdsa.PublicKey, error) {
	s = strings.TrimSpace(s)
	var der []byte
	if strings.HasPrefix(s, "-----BEGIN") {
		blk, _ := pem.Decode([]byte(s))
		if blk == nil {
			return nil, errors.New("invalid PEM public key")
		}
		der = blk.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(s); err != nil {
			return nil, errors.New("public key is not valid base64")
		}
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("authority keys must be ECDSA P-256")
	}
	return pub, nil
}

// SavePrivateKey writes a PKCS#8 PEM file readable only by the owner. It will
// not overwrite an existing file.
func SavePrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// LoadPrivateKey reads a PKCS#8 PEM ECDSA P-256 key.
func LoadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(raw)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s: not an ECDSA P-256 key", path)
	}
	return key, nil
}

// LoadSigners loads every *.key file in dir. A missing directory yields none.
func LoadSigners(dir string) ([]Signer, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.key"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Signer
	for _, p := range paths {
		key, err := LoadPrivateKey(p)
		if err != nil {
			return nil, err
		}
		id, err := KeyID(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		out = append(out, Signer{ID: id, Key: key})
	}
	return out, nil
}

// SignBlock fills in the header's signer and the payload commitments, then signs.
// A block that needs a timestamp goes through PrepareBlock first.
func SignBlock(s Signer, b *Block) error {
	if err := PrepareBlock(s, b); err != nil {
		return err
	}
	h := b.Hash()
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, h[:])
	if err != nil {
		return err
	}
	b.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// PrepareBlock fills in everything that ContentHash covers. The header's version
// stays as the caller set it, for the height; zero means the original format.
func PrepareBlock(s Signer, b *Block) error {
	root, err := PayloadsRoot(b.Payloads)
	if err != nil {
		return err
	}
	if b.Header.Version == 0 {
		b.Header.Version = Version
	}
	b.Header.PayloadsRoot = root
	b.Header.PayloadCount = len(b.Payloads)
	b.Header.RotationsRoot = RotationsRoot(b.Rotations)
	b.Header.RotationCount = len(b.Rotations)
	b.Header.Signer = s.ID
	return nil
}

// SignKeyChange produces this authority's approval of c.
func SignKeyChange(s Signer, c KeyChange) (RotationSig, error) {
	h := c.Hash()
	sig, err := ecdsa.SignASN1(rand.Reader, s.Key, h[:])
	if err != nil {
		return RotationSig{}, err
	}
	return RotationSig{Signer: s.ID, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// AddSignature merges sig into r, replacing an earlier one from the same key
// and keeping the list sorted by signer ID.
func (r *Rotation) AddSignature(sig RotationSig) {
	for i := range r.Signatures {
		if r.Signatures[i].Signer == sig.Signer {
			r.Signatures[i] = sig
			return
		}
	}
	r.Signatures = append(r.Signatures, sig)
	sort.Slice(r.Signatures, func(i, j int) bool { return r.Signatures[i].Signer < r.Signatures[j].Signer })
}

// VerifyKeyChangeSig checks one approval of c against the signer's public key.
func VerifyKeyChangeSig(pub *ecdsa.PublicKey, c KeyChange, s RotationSig) bool {
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return false
	}
	h := c.Hash()
	return ecdsa.VerifyASN1(pub, h[:], sig)
}

// Clone returns a copy that shares no memory with r.
func (r Rotation) Clone() Rotation {
	r.Signatures = append([]RotationSig(nil), r.Signatures...)
	return r
}
