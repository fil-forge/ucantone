// Package x25519 implements X25519 key-agreement keypairs for the multikey
// family.
//
// Unlike the signing keys in the sibling packages (ed25519, secp256k1), X25519
// keys cannot sign or verify: they exist purely for Elliptic-Curve
// Diffie-Hellman (ECDH) key agreement — for example the ECDH-ES+A256KW key
// wrapping used to seal a content-encryption key to a recipient. They therefore
// do not implement [github.com/fil-forge/ucantone/multikey.Signer] or
// [github.com/fil-forge/ucantone/multikey.Verifier] (which extend the signing
// ucan.Signer/ucan.Verifier interfaces); they are an independent keypair type
// that nonetheless follows the same multiformats and did:key conventions, so a
// public key round-trips through a did:key DID.
package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/key"
	"github.com/fil-forge/ucantone/multikey/internal/multiformat"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
)

const (
	// PublicKeyCode is the multicodec code for an X25519 public key
	// (x25519-pub, 0xec).
	PublicKeyCode = multicodec.X25519Pub
	// PrivateKeyCode is the multicodec code for an X25519 private key
	// (x25519-priv, 0x1302).
	PrivateKeyCode = multicodec.X25519Priv
)

// KeySize is the length in bytes of a raw X25519 public or private key.
const KeySize = 32

var curve = ecdh.X25519()

// KeyPair is an X25519 key-agreement keypair. It holds the private key and can
// perform ECDH against a peer's [PublicKey]. It cannot sign or verify.
type KeyPair struct {
	priv *ecdh.PrivateKey
}

// Generate creates a new random X25519 keypair.
func Generate() (*KeyPair, error) {
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating X25519 key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// FromRaw builds a keypair from raw (untagged) 32-byte X25519 private key bytes.
func FromRaw(b []byte) (*KeyPair, error) {
	priv, err := curve.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}
	return &KeyPair{priv: priv}, nil
}

// Decode decodes a keypair from multiformat-tagged private key bytes: the
// x25519-priv varint (0x1302) followed by the 32-byte raw private key.
func Decode(b []byte) (*KeyPair, error) {
	raw, err := multiformat.UntagWith(PrivateKeyCode, b, 0)
	if err != nil {
		return nil, err
	}
	return FromRaw(raw)
}

// Parse decodes a keypair from a multibase-encoded tagged private key string,
// the inverse of [KeyPair.String].
func Parse(s string) (*KeyPair, error) {
	_, b, err := multibase.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("decoding multibase string: %w", err)
	}
	return Decode(b)
}

// Code returns the multicodec code for the private key (x25519-priv).
func (k *KeyPair) Code() multicodec.Code { return PrivateKeyCode }

// Raw returns the 32-byte raw private key, without multiformats tags.
func (k *KeyPair) Raw() []byte { return k.priv.Bytes() }

// Bytes returns the private key bytes with the multiformats prefix varint
// (x25519-priv). This is the form to seal in custody (e.g. a vault) so the key
// type is recoverable on decode rather than assumed.
func (k *KeyPair) Bytes() []byte {
	return multiformat.TagWith(PrivateKeyCode, k.priv.Bytes())
}

// String returns the multibase (Base64pad) encoding of the tagged private key,
// matching the convention used for multikey signers.
func (k *KeyPair) String() string {
	s, _ := multibase.Encode(multibase.Base64pad, k.Bytes())
	return s
}

// PrivateKey returns the underlying [ecdh.PrivateKey].
func (k *KeyPair) PrivateKey() *ecdh.PrivateKey { return k.priv }

// Public returns the public half of the keypair.
func (k *KeyPair) Public() *PublicKey { return &PublicKey{pub: k.priv.PublicKey()} }

// KeyDID returns the did:key DID for the public half of the keypair.
func (k *KeyPair) KeyDID() did.DID { return k.Public().KeyDID() }

// ECDH performs X25519 Diffie-Hellman between this private key and the peer's
// public key, returning the raw shared secret. It returns an error rather than
// panicking when peer is nil or carries no public key, since peer keys may come
// from external input.
func (k *KeyPair) ECDH(peer *PublicKey) ([]byte, error) {
	if peer == nil || peer.pub == nil {
		return nil, fmt.Errorf("nil peer public key")
	}
	return k.priv.ECDH(peer.pub)
}

// PublicKey is an X25519 public key.
type PublicKey struct {
	pub *ecdh.PublicKey
}

// PublicFromRaw builds a public key from raw (untagged) 32-byte X25519 public
// key bytes.
func PublicFromRaw(b []byte) (*PublicKey, error) {
	pub, err := curve.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	return &PublicKey{pub: pub}, nil
}

// DecodePublic decodes a public key from multiformat-tagged bytes: the
// x25519-pub varint (0xec) followed by the 32-byte raw public key.
func DecodePublic(b []byte) (*PublicKey, error) {
	raw, err := multiformat.UntagWith(PublicKeyCode, b, 0)
	if err != nil {
		return nil, err
	}
	return PublicFromRaw(raw)
}

// ParsePublic decodes a public key from a multibase-encoded tagged string, the
// inverse of [PublicKey.String].
func ParsePublic(s string) (*PublicKey, error) {
	_, b, err := multibase.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("decoding multibase string: %w", err)
	}
	return DecodePublic(b)
}

// ParsePublicKeyDID decodes the X25519 public key from a did:key DID (e.g.
// did:key:z6LS...). It errors if the DID is not a did:key or does not encode an
// X25519 public key.
func ParsePublicKeyDID(d did.DID) (*PublicKey, error) {
	if d.Method() != key.Method {
		return nil, fmt.Errorf("invalid DID method: %s, expected: %s", d.Method(), key.Method)
	}
	enc, b, err := multibase.Decode(d.Identifier())
	if err != nil {
		return nil, err
	}
	if enc != multibase.Base58BTC {
		return nil, fmt.Errorf("not Base58BTC encoded")
	}
	return DecodePublic(b)
}

// Code returns the multicodec code for the public key (x25519-pub).
func (p *PublicKey) Code() multicodec.Code { return PublicKeyCode }

// Raw returns the 32-byte raw public key, without multiformats tags.
func (p *PublicKey) Raw() []byte { return p.pub.Bytes() }

// Bytes returns the public key bytes with the multiformats prefix varint
// (x25519-pub).
func (p *PublicKey) Bytes() []byte {
	return multiformat.TagWith(PublicKeyCode, p.pub.Bytes())
}

// PublicKey returns the underlying [ecdh.PublicKey].
func (p *PublicKey) PublicKey() *ecdh.PublicKey { return p.pub }

// String returns the multibase (Base58BTC) encoding of the tagged public key.
// This is the same encoding used as the identifier of the key's did:key DID.
func (p *PublicKey) String() string {
	s, _ := multibase.Encode(multibase.Base58BTC, p.Bytes())
	return s
}

// KeyDID returns the did:key DID corresponding to this public key, e.g.
// did:key:z6LS....
func (p *PublicKey) KeyDID() did.DID {
	return did.New(key.Method, p.String())
}
