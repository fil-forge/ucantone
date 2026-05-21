package server

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
)

// EventListener observes both halves of the request/response round trip a
// server handles: a request being decoded and a response being encoded.
// Register one with [WithEventListener].
type EventListener interface {
	RequestDecodeListener
	ResponseEncodeListener
}

// RequestDecodeListener is an observer with a function that is called after an
// execution request has been decoded by the codec.
type RequestDecodeListener interface {
	OnRequestDecode(ctx context.Context, container ucan.Container) error
}

// ResponseEncodeListener is an observer with a function that is called before
// an execution response is encoded by the codec.
type ResponseEncodeListener interface {
	OnResponseEncode(ctx context.Context, container ucan.Container) error
}
