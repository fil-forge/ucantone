package receipt

import "github.com/fil-forge/ucantone/ucan/invocation"

type Option = invocation.Option

var (
	WithExpiration   = invocation.WithExpiration
	WithNoExpiration = invocation.WithNoExpiration
	WithNonce        = invocation.WithNonce
	WithNoNonce      = invocation.WithNoNonce
	WithMetadata     = invocation.WithMetadata
	WithProofs       = invocation.WithProofs
	WithCause        = invocation.WithCause
)
