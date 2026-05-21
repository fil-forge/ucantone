package client

import (
	"context"

	"github.com/fil-forge/ucantone/ucan"
)

// EventListener observes both halves of the request/response round trip a
// client performs: a request being encoded and a response being decoded.
// Register one with [WithEventListener].
type EventListener interface {
	RequestEncodeListener
	ResponseDecodeListener
}

// RequestEncodeListener is an observer with a function that is called before an
// execution request is encoded by the codec.
type RequestEncodeListener interface {
	OnRequestEncode(ctx context.Context, container ucan.Container) error
}

// ResponseDecodeListener is an observer with a function that is called after an
// execution response is decoded by the codec.
type ResponseDecodeListener interface {
	OnResponseDecode(ctx context.Context, container ucan.Container) error
}
