package server

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
)

type EventListener = any

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
