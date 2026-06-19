package examples

import (
	cryptoEd25519 "crypto/ed25519"
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
)

func TestParseDIDKey(t *testing.T) {
	id, err := did.Parse("did:key:z6MkfBSb2hC6g3UGnqNmWfmGvPdfMorBpT2osm9bk9b4Cyqu")
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", id)
}

func TestParseDIDWeb(t *testing.T) {
	id, err := did.Parse("did:web:service.example.com")
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", id)
}

func TestGenerateDIDKey(t *testing.T) {
	principal, err := ed25519.GenerateIssuer()
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", principal.DID())
	// ed25519 principals are [principal.Signer]s
	sig := principal.Sign([]byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)
	// they have a private key (use format utility to multibase base64pad encode)
	fmt.Println("Private Key:", multikey.FormatSigner(principal))

	// which can be stored and decoded later...
	principal2, err := ed25519.Decode(principal.Bytes())
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", principal2.KeyDID())
}

func TestConvertEd25519SignerPrincipalToNativeEd25519PrivateKey(t *testing.T) {
	// generate ed25519 signer signer
	signer, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Key: %s / %s\n", multikey.FormatVerifier(signer.Verifier().(multikey.Verifier)), multikey.FormatSigner(signer))

	// convert to native ed25519 private key
	sk := cryptoEd25519.NewKeyFromSeed(signer.Raw())
	sig := cryptoEd25519.Sign(sk, []byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)

	// convert back to ed25519 signer
	signer2, err := ed25519.FromRaw(sk.Seed())
	if err != nil {
		panic(err)
	}
	fmt.Printf("Key: %s / %s\n", multikey.FormatVerifier(signer2.Verifier().(multikey.Verifier)), multikey.FormatSigner(signer2))

	// signature should match signature above...since it's the same private key
	sig = signer2.Sign([]byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)
}
