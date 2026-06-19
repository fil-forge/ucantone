package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fil-forge/ucantone/did"
)

const Method = "web"

const WellKnownDIDPath = "/.well-known/did.json"

var _ did.Resolver = (*Resolver)(nil)

// Resolver resolves a did:web DID to a DID Document by fetching the document
// over HTTPS (or HTTP if configured), according to the did:web method spec.
// https://w3c-ccg.github.io/did-method-web/#read-resolve
type Resolver struct {
	cfg config
}

func NewResolver(options ...Option) (*Resolver, error) {
	cfg := &config{
		// default timeout of 10 seconds
		timeout:  10 * time.Second,
		insecure: false,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return &Resolver{cfg: *cfg}, nil
}

func (r *Resolver) Resolve(ctx context.Context, d did.DID) (did.Document, error) {
	if err := did.ValidateMethod(d, Method); err != nil {
		return did.Document{}, err
	}

	if r.cfg.globs != nil {
		match := false
		for _, g := range r.cfg.globs {
			if match = g.Match(d.Identifier()); match {
				break
			}
		}
		if !match {
			return did.Document{}, fmt.Errorf("resolution of %s via HTTP not permitted", d)
		}
	}

	url := documentURL(d, r.cfg.insecure)

	httpClient := &http.Client{
		Timeout:   r.cfg.timeout,
		Transport: r.cfg.transport,
	}
	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		return did.Document{}, fmt.Errorf("creating HTTP request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return did.Document{}, fmt.Errorf("performing HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return did.Document{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var doc did.Document
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return did.Document{}, fmt.Errorf("parsing DID document JSON: %w", err)
	}

	return doc, nil
}

func documentURL(d did.DID, insecure bool) url.URL {
	scheme := "https"
	if insecure {
		scheme = "http"
	}

	segments := strings.Split(d.Identifier(), ":")
	host := segments[0]
	// Unescape percent-encoded colons in the host, to support port numbers.
	host = strings.ReplaceAll(host, "%3A", ":")
	path := ""
	if len(segments) > 1 {
		path = "/" + strings.Join(segments[1:], "/") + "/did.json"
	} else {
		path = WellKnownDIDPath
	}
	return url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}
}
