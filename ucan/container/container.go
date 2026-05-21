package container

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/container/datamodel"
	"github.com/fil-forge/ucantone/ucan/delegation"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/fil-forge/ucantone/ucan/receipt"
	"github.com/ipfs/go-cid"
)

const (
	Raw           = byte(0x40) // raw bytes, no compression
	Base64        = byte(0x42) // base64 std padding, no compression
	Base64url     = byte(0x43) // base64 url (no padding), no compression
	RawGzip       = byte(0x44) // raw bytes, gzip
	Base64Gzip    = byte(0x45) // base64 std padding, gzip
	Base64urlGzip = byte(0x46) // base64 url (no padding), gzip
)

// FormatCodec converts a container codec code into a human readable string.
func FormatCodec(codec byte) string {
	switch codec {
	case Raw:
		return "raw"
	case Base64:
		return "base64"
	case Base64url:
		return "base64url"
	case RawGzip:
		return "raw+gzip"
	case Base64Gzip:
		return "base64+gzip"
	case Base64urlGzip:
		return "base64url+gzip"
	default:
		return "unknown"
	}
}

// Container contains any number of UCAN [ucan.Token]s of any kind.
//
// https://github.com/ucan-wg/container
type Container struct {
	cids  *cid.Set
	invs  []ucan.Invocation
	rcpts []ucan.Receipt
	dlgs  []ucan.Delegation
}

func (c *Container) Delegations() []ucan.Delegation {
	return c.dlgs
}

func (c *Container) Delegation(root cid.Cid) (ucan.Delegation, bool) {
	for _, dlg := range c.dlgs {
		if dlg.Link() == root {
			return dlg, true
		}
	}
	return nil, false
}

func (c *Container) Invocations() []ucan.Invocation {
	return c.invs
}

func (c *Container) Receipts() []ucan.Receipt {
	return c.rcpts
}

func (c *Container) Receipt(task cid.Cid) (ucan.Receipt, bool) {
	for _, rcpt := range c.rcpts {
		if rcpt.Ran() == task {
			return rcpt, true
		}
	}
	return nil, false
}

func (c *Container) MarshalCBOR(w io.Writer) error {
	tokens, err := encodeTokens(c.invs, c.dlgs, c.rcpts)
	if err != nil {
		return err
	}
	model := datamodel.ContainerModel{Ctn1: tokens}
	return model.MarshalCBOR(w)
}

func (c *Container) UnmarshalCBOR(r io.Reader) error {
	model := datamodel.ContainerModel{}
	if err := model.UnmarshalCBOR(r); err != nil {
		return fmt.Errorf("unmarshaling container model CBOR: %w", err)
	}
	invs, dlgs, rcpts, err := decodeTokens(model.Ctn1)
	if err != nil {
		return fmt.Errorf("decoding container tokens: %w", err)
	}
	*c = Container{
		invs:  invs,
		dlgs:  dlgs,
		rcpts: rcpts,
	}
	return nil
}

func (c *Container) MarshalDagJSON(w io.Writer) error {
	tokens, err := encodeTokens(c.invs, c.dlgs, c.rcpts)
	if err != nil {
		return err
	}
	model := datamodel.ContainerModel{Ctn1: tokens}
	return model.MarshalDagJSON(w)
}

func (c *Container) UnmarshalDagJSON(r io.Reader) error {
	model := datamodel.ContainerModel{}
	if err := model.UnmarshalDagJSON(r); err != nil {
		return fmt.Errorf("unmarshaling container model DAG-JSON: %w", err)
	}
	invs, dlgs, rcpts, err := decodeTokens(model.Ctn1)
	if err != nil {
		return fmt.Errorf("decoding container tokens: %w", err)
	}
	*c = Container{
		invs:  invs,
		dlgs:  dlgs,
		rcpts: rcpts,
	}
	return nil
}

type Option func(c *Container)

func WithInvocations(invocations ...ucan.Invocation) Option {
	return func(c *Container) {
		for _, inv := range invocations {
			if c.cids.Visit(inv.Link()) {
				c.invs = append(c.invs, inv)
			}
		}
	}
}

func WithDelegations(delegations ...ucan.Delegation) Option {
	return func(c *Container) {
		for _, dlg := range delegations {
			if c.cids.Visit(dlg.Link()) {
				c.dlgs = append(c.dlgs, dlg)
			}
		}
	}
}

func WithReceipts(receipts ...ucan.Receipt) Option {
	return func(c *Container) {
		for _, rcpt := range receipts {
			if c.cids.Visit(rcpt.Link()) {
				c.rcpts = append(c.rcpts, rcpt)
			}
		}
	}
}

func New(options ...Option) *Container {
	ct := Container{cids: cid.NewSet()}
	for _, opt := range options {
		opt(&ct)
	}
	return &ct
}

func Encode(codec byte, container ucan.Container) ([]byte, error) {
	c, ok := container.(*Container)
	if !ok {
		c = &Container{
			invs:  container.Invocations(),
			dlgs:  container.Delegations(),
			rcpts: container.Receipts(),
		}
	}

	var buf bytes.Buffer
	err := c.MarshalCBOR(&buf)
	if err != nil {
		return nil, fmt.Errorf("marshaling container to CBOR: %w", err)
	}

	var out []byte
	if codec == RawGzip || codec == Base64Gzip || codec == Base64urlGzip {
		var gzbuf bytes.Buffer
		gz := gzip.NewWriter(&gzbuf)
		_, err := io.Copy(gz, &buf)
		if err != nil {
			gz.Close()
			return nil, fmt.Errorf("compressing container data: %w", err)
		}
		if err := gz.Close(); err != nil {
			return nil, fmt.Errorf("closing gzip writer: %w", err)
		}
		out = gzbuf.Bytes()
	} else {
		out = buf.Bytes()
	}

	switch codec {
	case Raw, RawGzip:
		// nothing to do
		break
	case Base64, Base64Gzip:
		out = []byte(base64.StdEncoding.EncodeToString(out))
	case Base64url, Base64urlGzip:
		out = []byte(base64.RawURLEncoding.EncodeToString(out))
	default:
		return nil, fmt.Errorf("unknown codec: 0x%02x", codec)
	}

	return append([]byte{codec}, out...), nil
}

func Decode(input []byte) (*Container, error) {
	if len(input) == 0 {
		return nil, errors.New("empty container bytes")
	}
	codec := input[0]
	var compressed []byte
	switch codec {
	case Raw, RawGzip:
		compressed = input[1:]
	case Base64, Base64Gzip:
		r, err := base64.StdEncoding.DecodeString(string(input[1:]))
		if err != nil {
			return nil, fmt.Errorf("decoding base64: %w", err)
		}
		compressed = r
	case Base64url, Base64urlGzip:
		r, err := base64.RawURLEncoding.DecodeString(string(input[1:]))
		if err != nil {
			return nil, fmt.Errorf("decoding base64url: %w", err)
		}
		compressed = r
	default:
		return nil, fmt.Errorf("unknown codec: 0x%02x", codec)
	}

	var raw []byte
	if codec == RawGzip || codec == Base64Gzip || codec == Base64urlGzip {
		gz, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			return nil, fmt.Errorf("creating gzip reader: %w", err)
		}
		defer gz.Close()
		if raw, err = io.ReadAll(gz); err != nil {
			return nil, fmt.Errorf("reading gzipped data: %w", err)
		}
	} else {
		raw = compressed // not compressed
	}

	ct := Container{}
	err := ct.UnmarshalCBOR(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	return &ct, nil
}

func encodeTokens(invs []ucan.Invocation, dlgs []ucan.Delegation, rcpts []ucan.Receipt) ([][]byte, error) {
	var tokens [][]byte
	for _, inv := range invs {
		b, err := invocation.Encode(inv)
		if err != nil {
			return nil, fmt.Errorf("encoding invocation: %w", err)
		}
		tokens = append(tokens, b)
	}
	for _, dlg := range dlgs {
		b, err := delegation.Encode(dlg)
		if err != nil {
			return nil, fmt.Errorf("encoding delegation: %w", err)
		}
		tokens = append(tokens, b)
	}
	for _, rcpt := range rcpts {
		b, err := receipt.Encode(rcpt)
		if err != nil {
			return nil, fmt.Errorf("encoding receipt: %w", err)
		}
		tokens = append(tokens, b)
	}

	// Sort tokens bytewise to ensure determism.
	// https://github.com/ucan-wg/container#21-inner-structure
	slices.SortFunc(tokens, bytes.Compare)

	return tokens, nil
}

func decodeTokens(tokens [][]byte) ([]ucan.Invocation, []ucan.Delegation, []ucan.Receipt, error) {
	invs := []ucan.Invocation{}
	dlgs := []ucan.Delegation{}
	rcpts := []ucan.Receipt{}
	for _, b := range tokens {
		if dlg, err := delegation.Decode(b); err == nil {
			dlgs = append(dlgs, dlg)
			continue
		}
		if rcpt, err := receipt.Decode(b); err == nil {
			rcpts = append(rcpts, rcpt)
			continue
		}
		if inv, err := invocation.Decode(b); err == nil {
			invs = append(invs, inv)
			continue
		}
	}
	return invs, dlgs, rcpts, nil
}
