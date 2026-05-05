package transport

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
)

// Request is an interface that provides a context.
type Request interface {
	Context() context.Context
}

type Response = any

type InboundCodec[Req Request, Res Response] interface {
	Decode(Req) (ucan.Container, error)
	Encode(ucan.Container) (Res, error)
}

type OutboundCodec[Req Request, Res Response] interface {
	Encode(ucan.Container) (Req, error)
	Decode(Res) (ucan.Container, error)
}

type RoundTripper[Req Request, Res Response] interface {
	RoundTrip(Req) (Res, error)
}
