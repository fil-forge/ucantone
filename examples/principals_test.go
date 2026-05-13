package examples

import (
	cryptoEd25519 "crypto/ed25519"
	"fmt"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/principal/ed25519"
	"github.com/fil-forge/ucantone/principal/signer"
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
	principal, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", principal.DID())
	// ed25519 principals are [principal.Signer]s
	sig := principal.Sign([]byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)
	// they have a private key (use format utility to multibase base64pad encode)
	fmt.Println("Private Key:", signer.Format(principal))

	// which can be stored and decoded later...
	principal2, err := ed25519.Decode(principal.Bytes())
	if err != nil {
		panic(err)
	}
	fmt.Println(principal2.DID())
}

func TestWrapDIDWeb(t *testing.T) {
	webPrincipal, err := did.Parse("did:web:service.example.com")
	if err != nil {
		panic(err)
	}
	signerPrincipal, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", signerPrincipal.DID())

	principal, err := signer.Wrap(signerPrincipal, webPrincipal)
	if err != nil {
		panic(err)
	}
	// DID is did:web:
	fmt.Println("DID (wrapped):", principal.DID())
	// ..but this principal is a [principal.Signer]
	sig := principal.Sign([]byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)
	// ...and has a private key (use format utility to multibase base64pad encode)
	fmt.Println("Private Key:", signer.Format(principal))
	// ...which can be stored and decoded later
	signerPrincipal2, err := ed25519.Decode(principal.Bytes())
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", signerPrincipal2.DID())
	// ...and re-wrapped
	principal2, err := signer.Wrap(signerPrincipal2, webPrincipal)
	if err != nil {
		panic(err)
	}
	fmt.Println("DID (wrapped):", principal2.DID())
}

func TestConvertEd25519SignerPrincipalToNativeEd25519PrivateKey(t *testing.T) {
	// generate ed25519 signer principal
	principal, err := ed25519.Generate()
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", principal.DID())

	// convert to native ed25519 private key
	sk := cryptoEd25519.NewKeyFromSeed(principal.Raw())
	sig := cryptoEd25519.Sign(sk, []byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)

	// convert back to ed25519 signer principal
	principal2, err := ed25519.FromRaw(sk.Seed())
	if err != nil {
		panic(err)
	}
	fmt.Println("DID:", principal2.DID())

	// signature should match signature above...since it's the same private key
	sig = principal2.Sign([]byte{1, 2, 3})
	fmt.Printf("Signature: 0x%x\n", sig)
}
