package testutil

import (
	"net/url"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/multikey"
	"github.com/fil-forge/ucantone/multikey/ed25519"
)

var (
	// did:key:z6Mkk89bC3JrVqKie71YEcc5M1SMVxuCgNx6zLZ8SYJsxALi
	alice, _ = ed25519.Parse("MgCZT5vOnYZoVAeyjnzuJIVY9J4LNtJ+f8Js0cTPuKUpFnQ==")
	Alice    = multikey.KeyIssuer(alice)

	// did:key:z6MkffDZCkCTWreg8868fG1FGFogcJj5X6PY93pPcWDn9bob
	bob, _ = ed25519.Parse("MgCYbj5AJfVvdrjkjNCxB3iAUwx7RQHVQ7H1sKyHy46IosQ==")
	Bob    = multikey.KeyIssuer(bob)

	// did:key:z6MkwYkD48SUrPhQ5Sf8qk5L8FW2L32Ze4guLnZXY4DrDCAR
	carol, _ = ed25519.Parse("MgCa5pEVgZbqGILBFD3/TAd1a1OOJMuPsVz/uxS9ceU5jeg==")
	Carol    = multikey.KeyIssuer(carol)

	// did:key:z6MktafZTREjJkvV5mfJxcLpNBoVPwDLhTuMg9ng7dY4zMAL
	mallory, _ = ed25519.Parse("MgCYtH0AvYxiQwBG6+ZXcwlXywq9tI50G2mCAUJbwrrahkA==")
	Mallory    = multikey.KeyIssuer(mallory)

	// did:key:z6Mkk3mDiu74xxyYEff5X1p568fVqEMczj5keYPT8qVMNsVC
	service, _ = ed25519.Parse("MgCZyxtpD6SFBcXCXUKPTkLrc2+RlmaBjL/tMgWCT3+MUlw==")
	Service    = multikey.KeyIssuer(service)

	// did:web:test.storacha.network
	webServiceDID, _ = did.Parse("did:web:test.storacha.network")
	WebService       = multikey.NewIssuer(webServiceDID, service)
	WebServiceSigner = service

	TestURL, _ = url.Parse("https://test.storacha.network")
)
