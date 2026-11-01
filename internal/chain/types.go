// Package chain implements the eidchain data model and consensus rules: a
// proof-of-authority chain of JSON blocks whose payloads are verbatim JSON
// strings with detached CAdES signatures made by eID certificates.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const (
	// Version is the block and genesis format version.
	Version = 1
	// DefaultMaxPayloadBytes is the per-payload size cap (10 KiB).
	DefaultMaxPayloadBytes = 10 * 1024

	genesisDomain  = "eidchain/genesis/v1\n"
	blockDomain    = "eidchain/block/v1\n"
	rotationDomain = "eidchain/rotation/v1\n"
	payloadDomain  = "eidchain/payload/v1\n"
)

// Hash is a SHA-256 digest, rendered as lowercase hex in JSON.
type Hash [32]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// Short is the first 12 hex characters, for logs.
func (h Hash) Short() string { return h.String()[:12] }

func (h Hash) IsZero() bool { return h == Hash{} }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

func (h *Hash) UnmarshalText(b []byte) error {
	parsed, err := ParseHash(string(b))
	if err != nil {
		return err
	}
	*h = parsed
	return nil
}

// ParseHash parses a 64-character hex string.
func ParseHash(s string) (Hash, error) {
	var h Hash
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(h) {
		return h, fmt.Errorf("invalid hash %q: want 64 hex characters", s)
	}
	copy(h[:], raw)
	return h, nil
}

// Authority is one entry of the authority set: an ECDSA P-256 public key.
type Authority struct {
	Name      string `json:"name,omitempty"`
	PublicKey string `json:"publicKey"` // base64 of the DER SubjectPublicKeyInfo
}

// Rules are consensus parameters fixed by the genesis block.
type Rules struct {
	// RequireNonRepudiation demands the non-repudiation (contentCommitment) key
	// usage on payload signing certificates, which keeps authentication
	// certificates from signing records.
	RequireNonRepudiation bool `json:"requireNonRepudiation"`
	MaxPayloadBytes       int  `json:"maxPayloadBytes"`
	// RotationQuorum is how many distinct currently valid authority keys must
	// sign a key rotation (1..N). The default is a majority, N/2+1.
	RotationQuorum int `json:"rotationQuorum"`
	// MaxRotationsPerBlock caps control messages in one block.
	MaxRotationsPerBlock int `json:"maxRotationsPerBlock"`
}

// Genesis is the root of a chain. Its hash identifies the chain: every rule a
// node applies (authorities, trusted CAs, limits) comes from here.
type Genesis struct {
	Type         string      `json:"type"` // always "eidchain-genesis"
	Version      int         `json:"version"`
	Created      int64       `json:"created"` // unix seconds
	Message      string      `json:"message"`
	Authorities  []Authority `json:"authorities"`
	TrustAnchors []string    `json:"trustAnchors"` // PEM certificates (roots and intermediates)
	Rules        Rules       `json:"rules"`
}

// Header is what the authority signs (via the block hash).
type Header struct {
	Version      int    `json:"version"`
	Height       uint64 `json:"height"`
	Prev         Hash   `json:"prev"`
	Time         int64  `json:"time"`         // unix seconds, from the signer's clock
	PayloadsRoot Hash   `json:"payloadsRoot"` // zero if there are no payloads
	PayloadCount int    `json:"payloadCount"`
	// RotationsRoot commits to the key-rotation control messages (zero if none).
	RotationsRoot Hash   `json:"rotationsRoot"`
	RotationCount int    `json:"rotationCount"`
	Signer        string `json:"signer"` // authority key ID (hex SHA-256 of the SPKI)
}

// KeyChange replaces one authority key by another. It is a control message:
// not an eID record, but signed by authority ECDSA keys.
type KeyChange struct {
	Type   string `json:"type"`   // "replace"
	Chain  Hash   `json:"chain"`  // the genesis hash: the change is for this chain only
	Seq    uint64 `json:"seq"`    // rotations already applied before this one; prevents replay
	Old    string `json:"old"`    // key ID of the authority being replaced
	NewKey string `json:"newKey"` // base64 DER SPKI of the replacement (ECDSA P-256)
}

// Hash is what authorities sign.
func (c KeyChange) Hash() Hash {
	return sha256.Sum256(append([]byte(rotationDomain), canonical(c)...))
}

// RotationSig is one authority's approval of a KeyChange.
type RotationSig struct {
	Signer    string `json:"signer"`    // key ID
	Signature string `json:"signature"` // base64 ASN.1 ECDSA over KeyChange.Hash()
}

// Rotation is a KeyChange with its approvals, sorted by signer ID.
type Rotation struct {
	Change     KeyChange     `json:"change"`
	Signatures []RotationSig `json:"signatures"`
}

// PayloadEntry is one record. Payload is stored verbatim: the exact bytes of
// the JSON text are what Signature covers.
type PayloadEntry struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`      // base64 DER CMS: detached CAdES-B-B
	OCSP      string `json:"ocsp,omitempty"` // base64 DER OCSP response; committed to but not a validity rule
}

// ID identifies a record: these bytes, signed by this certificate. Two people may
// sign the same text and get separate records. The signature bytes are left out
// on purpose: anyone can vary those (ECDSA values, unsigned attributes), which
// would let an old record be replayed under a new ID, as would the OCSP response.
func (e PayloadEntry) ID() Hash {
	var signer []byte
	if sig, err := base64.StdEncoding.DecodeString(e.Signature); err == nil {
		if h, err := signerCertHash(sig); err == nil {
			signer = h[:]
		}
	}
	if signer == nil { // unparsable: it will fail validation, so any stable value does
		signer = []byte(e.Signature)
	}
	var buf bytes.Buffer
	buf.WriteString(payloadDomain)
	putChunk(&buf, []byte(e.Payload))
	putChunk(&buf, signer)
	return sha256.Sum256(buf.Bytes())
}

// Block is a signed set of payloads.
type Block struct {
	Header    Header         `json:"header"`
	Payloads  []PayloadEntry `json:"payloads"`
	Rotations []Rotation     `json:"rotations,omitempty"`
	Signature string         `json:"signature"` // base64 ASN.1 ECDSA signature over the block hash
}

// canonical encodes v as compact JSON, struct fields in declaration order and
// no HTML escaping. This is the byte string that gets hashed.
func canonical(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err) // only plain structs are passed in
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// Hash returns the genesis hash, which is the chain identifier.
func (g *Genesis) Hash() Hash {
	return sha256.Sum256(append([]byte(genesisDomain), canonical(g)...))
}

// HashHeader returns the block hash.
func HashHeader(h Header) Hash {
	return sha256.Sum256(append([]byte(blockDomain), canonical(h)...))
}

// Hash returns the block's hash.
func (b *Block) Hash() Hash { return HashHeader(b.Header) }

func putChunk(buf *bytes.Buffer, b []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	buf.Write(n[:])
	buf.Write(b)
}

// leafHash commits to the payload text, the signature and the OCSP response.
func leafHash(e PayloadEntry) (Hash, error) {
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return Hash{}, errors.New("signature is not valid base64")
	}
	ocsp, err := base64.StdEncoding.DecodeString(e.OCSP)
	if err != nil {
		return Hash{}, errors.New("ocsp is not valid base64")
	}
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	putChunk(&buf, []byte(e.Payload))
	putChunk(&buf, sig)
	putChunk(&buf, ocsp)
	return sha256.Sum256(buf.Bytes()), nil
}

// PayloadsRoot computes the RFC 6962 style Merkle root over the entries.
func PayloadsRoot(entries []PayloadEntry) (Hash, error) {
	if len(entries) == 0 {
		return Hash{}, nil
	}
	leaves := make([]Hash, len(entries))
	for i, e := range entries {
		l, err := leafHash(e)
		if err != nil {
			return Hash{}, fmt.Errorf("payload %d: %w", i, err)
		}
		leaves[i] = l
	}
	return merkle(leaves), nil
}

func merkle(leaves []Hash) Hash {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := merkle(leaves[:k]), merkle(leaves[k:])
	return sha256.Sum256(append(append([]byte{0x01}, l[:]...), r[:]...))
}

// RotationsRoot commits to the rotations, including their signatures.
func RotationsRoot(rs []Rotation) Hash {
	if len(rs) == 0 {
		return Hash{}
	}
	leaves := make([]Hash, len(rs))
	for i, r := range rs {
		leaves[i] = sha256.Sum256(append([]byte{0x00}, canonical(r)...))
	}
	return merkle(leaves)
}
