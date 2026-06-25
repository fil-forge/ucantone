//go:build !codegen

package plc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	did "github.com/fil-forge/ucantone/did"
)

type DirectoryClient struct {
	Resolver
	endpoint url.URL
	client   *http.Client
}

// NewDirectoryClient creates a new DirectoryClient that can be used to fetch,
// update, and deactivate PLC operations at a directory at the given endpoint.
// The client can be configured with options such as timeout and transport.
func NewDirectoryClient(endpoint url.URL, options ...Option) (*DirectoryClient, error) {
	cfg := config{}
	for _, opt := range options {
		opt(&cfg)
	}
	if cfg.timeout <= 0 {
		// default timeout of 10 seconds
		cfg.timeout = 10 * time.Second
	}
	c := http.Client{
		Timeout:   cfg.timeout,
		Transport: cfg.transport,
	}
	resolver := Resolver{endpoint: endpoint, client: &c}
	return &DirectoryClient{endpoint: endpoint, client: &c, Resolver: resolver}, nil
}

// Last fetches the last operation for the given did:plc DID from the configured
// directory.
func (c *DirectoryClient) Last(ctx context.Context, d did.DID) (*SignedOperation, error) {
	if err := did.ValidateMethod(d, Method); err != nil {
		return nil, err
	}
	url := c.endpoint.JoinPath(d.String(), "log", "last")
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	var op SignedOperation
	if err := op.UnmarshalDagJSON(resp.Body); err != nil {
		return nil, fmt.Errorf("parsing signed operation JSON: %w", err)
	}
	if op.Type == TombstoneType {
		if op.Previous == nil {
			return nil, fmt.Errorf("invalid tombstone operation: missing previous operation")
		}
		t := &SignedTombstone{
			Type:      TombstoneType,
			Previous:  *op.Previous,
			Signature: op.Signature,
		}
		return nil, &DeactivatedDIDError{Operation: t}
	}
	return &op, nil
}

// dagJSONMarshaler is implemented by signed PLC operations and tombstones.
type dagJSONMarshaler interface {
	MarshalDagJSON(w io.Writer) error
}

// post submits the given DagJSON-encodable operation to the configured
// directory for the given did:plc DID.
func (c *DirectoryClient) post(ctx context.Context, d did.DID, op dagJSONMarshaler) error {
	if err := did.ValidateMethod(d, Method); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := op.MarshalDagJSON(&buf); err != nil {
		return fmt.Errorf("marshaling operation to JSON: %w", err)
	}
	url := c.endpoint.JoinPath(d.String())
	req, err := http.NewRequestWithContext(ctx, "POST", url.String(), &buf)
	if err != nil {
		return fmt.Errorf("creating HTTP request: %w", err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

// Update publishes the given signed operation to the configured directory.
func (c *DirectoryClient) Update(ctx context.Context, d did.DID, op *SignedOperation) error {
	return c.post(ctx, d, op)
}

// Deactivate publishes the given signed tombstone to the configured directory,
// deactivating the DID.
func (c *DirectoryClient) Deactivate(ctx context.Context, d did.DID, op *SignedTombstone) error {
	return c.post(ctx, d, op)
}

type DeactivatedDIDError struct {
	Operation *SignedTombstone
}

func (e *DeactivatedDIDError) Error() string {
	return "DID has been deactivated"
}
