package transport

import (
	"fmt"
	"io"
	"net/http"

	"github.com/fil-forge/ucantone/ipld/codec/dagcbor"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container"
)

var (
	DefaultHTTPInboundCodec  = &HTTPInboundCodec{}
	DefaultHTTPOutboundCodec = &HTTPOutboundCodec{}
)

type HTTPInboundCodec struct{}

var _ InboundCodec[*http.Request, *http.Response] = (*HTTPInboundCodec)(nil)

func (h *HTTPInboundCodec) Decode(r *http.Request) (ucan.Container, error) {
	if r.Header.Get("Content-Type") != dagcbor.ContentType {
		return nil, fmt.Errorf("invalid content type %q, expected %q", r.Header.Get("Content-Type"), dagcbor.ContentType)
	}
	ct := container.Container{}
	if err := ct.UnmarshalCBOR(r.Body); err != nil {
		return nil, fmt.Errorf("unmarshaling request container: %w", err)
	}
	return &ct, nil
}

func (h *HTTPInboundCodec) Encode(c ucan.Container) (*http.Response, error) {
	ct, ok := c.(*container.Container)
	if !ok {
		ct = container.New(
			container.WithInvocations(c.Invocations()...),
			container.WithDelegations(c.Delegations()...),
			container.WithReceipts(c.Receipts()...),
		)
	}
	r, w := io.Pipe()
	go func() {
		err := ct.MarshalCBOR(w)
		w.CloseWithError(err)
	}()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       r,
		Header:     http.Header{},
	}
	resp.Header.Set("Content-Type", dagcbor.ContentType)
	return resp, nil
}

type HTTPResponseContainer struct {
	ucan.Container
	Response *http.Response
}

type HTTPOutboundCodec struct{}

var _ OutboundCodec[*http.Request, *http.Response] = (*HTTPOutboundCodec)(nil)

func (h *HTTPOutboundCodec) Encode(c ucan.Container) (*http.Request, error) {
	ct, ok := c.(*container.Container)
	if !ok {
		ct = container.New(
			container.WithInvocations(c.Invocations()...),
			container.WithDelegations(c.Delegations()...),
			container.WithReceipts(c.Receipts()...),
		)
	}
	r, w := io.Pipe()
	go func() {
		err := ct.MarshalCBOR(w)
		w.CloseWithError(err)
	}()
	req := &http.Request{
		Method: http.MethodPost,
		Body:   r,
		Header: http.Header{},
	}
	req.Header.Set("Content-Type", dagcbor.ContentType)
	return req, nil
}

func (h *HTTPOutboundCodec) Decode(r *http.Response) (ucan.Container, error) {
	if r.Header.Get("Content-Type") != dagcbor.ContentType {
		return nil, fmt.Errorf("invalid content type %q, expected %q", r.Header.Get("Content-Type"), dagcbor.ContentType)
	}
	ct := container.Container{}
	if err := ct.UnmarshalCBOR(r.Body); err != nil {
		return nil, fmt.Errorf("unmarshaling response container: %w", err)
	}
	return &HTTPResponseContainer{Container: &ct, Response: r}, nil
}
