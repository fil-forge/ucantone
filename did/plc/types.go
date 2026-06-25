package plc

import (
	"bytes"
	"fmt"

	"github.com/fil-forge/ucantone/did"
	cid "github.com/ipfs/go-cid"
	multihash "github.com/multiformats/go-multihash/core"
)

const (
	OperationType = "plc_operation"
	TombstoneType = "plc_tombstone"
)

// Signer is an entity that can sign a payload.
type Signer interface {
	// Sign takes a byte encoded message and produces a verifiable signature.
	Sign(msg []byte) []byte
}

// Verifier represents an entity that can verify signatures.
type Verifier interface {
	// Verify takes a byte encoded message and verifies that it is signed by
	// corresponding signer.
	Verify(msg []byte, sig []byte) bool
}

// Operation represents a PLC operation that can be used to create or update a
// PLC DID.
type Operation struct {
	Type                string             `cborgen:"type,const=plc_operation" dagjsongen:"type,const=plc_operation"`
	VerificationMethods map[string]did.DID `cborgen:"verificationMethods" dagjsongen:"verificationMethods"`
	RotationKeys        []did.DID          `cborgen:"rotationKeys" dagjsongen:"rotationKeys"`
	AlsoKnownAs         []string           `cborgen:"alsoKnownAs" dagjsongen:"alsoKnownAs"`
	Services            map[string]Service `cborgen:"services" dagjsongen:"services"`
	// String encoded CID of the previous operation in the chain, if any. If this
	// is the first operation in the chain, this field is null.
	Previous *string `cborgen:"prev" dagjsongen:"prev"`
}

type SignedOperation struct {
	Type                string             `cborgen:"type,const=plc_operation" dagjsongen:"type,const=plc_operation"`
	VerificationMethods map[string]did.DID `cborgen:"verificationMethods" dagjsongen:"verificationMethods"`
	RotationKeys        []did.DID          `cborgen:"rotationKeys" dagjsongen:"rotationKeys"`
	AlsoKnownAs         []string           `cborgen:"alsoKnownAs" dagjsongen:"alsoKnownAs"`
	Services            map[string]Service `cborgen:"services" dagjsongen:"services"`
	// String encoded CID of the previous operation in the chain, if any. If this
	// is the first operation in the chain, this field is null.
	Previous  *string `cborgen:"prev" dagjsongen:"prev"`
	Signature string  `cborgen:"sig" dagjsongen:"sig"`
}

type Service struct {
	Type     string `cborgen:"type" dagjsongen:"type"`
	Endpoint string `cborgen:"endpoint" dagjsongen:"endpoint"`
}

type Tombstone struct {
	Type     string `cborgen:"type,const=plc_tombstone" dagjsongen:"type,const=plc_tombstone"`
	Previous string `cborgen:"prev" dagjsongen:"prev"`
}

type SignedTombstone struct {
	Type      string `cborgen:"type,const=plc_tombstone" dagjsongen:"type,const=plc_tombstone"`
	Previous  string `cborgen:"prev" dagjsongen:"prev"`
	Signature string `cborgen:"sig" dagjsongen:"sig"`
}

type opConfig struct {
	verificationMethods map[string]did.DID
	rotationKeys        []did.DID
	alsoKnownAs         []string
	services            map[string]Service
}

type OperationOption func(*opConfig)

func WithVerificationMethods(methods map[string]did.DID) OperationOption {
	return func(c *opConfig) {
		if c.verificationMethods == nil {
			c.verificationMethods = make(map[string]did.DID, len(methods))
		}
		for k, v := range methods {
			c.verificationMethods[k] = v
		}
	}
}

func WithRotationKeys(keys []did.DID) OperationOption {
	return func(c *opConfig) {
		c.rotationKeys = append(c.rotationKeys, keys...)
	}
}

func WithAlsoKnownAs(alsoKnownAs []string) OperationOption {
	return func(c *opConfig) {
		c.alsoKnownAs = append(c.alsoKnownAs, alsoKnownAs...)
	}
}

func WithServices(services map[string]Service) OperationOption {
	return func(c *opConfig) {
		if c.services == nil {
			c.services = make(map[string]Service, len(services))
		}
		for k, v := range services {
			c.services[k] = v
		}
	}
}

// NewOperation creates a new PLC operation with the given previous operation
// CID and options.
func NewOperation(prev *cid.Cid, options ...OperationOption) *Operation {
	cfg := opConfig{}
	for _, option := range options {
		option(&cfg)
	}
	var prevStr *string
	if prev != nil {
		s := prev.String()
		prevStr = &s
	}
	return &Operation{
		Type:                OperationType,
		VerificationMethods: cfg.verificationMethods,
		RotationKeys:        cfg.rotationKeys,
		AlsoKnownAs:         cfg.alsoKnownAs,
		Services:            cfg.services,
		Previous:            prevStr,
	}
}

// NewFromPreviousOperation creates a new PLC operation that updates the given
// previous operation with the provided options. The new operation will have the
// previous verification methods, rotation keys, also known as, and services as
// the previous operation, merged with the values passed in the options.
func NewFromPreviousOperation(prev *SignedOperation, options ...OperationOption) (*Operation, error) {
	cfg := opConfig{
		verificationMethods: prev.VerificationMethods,
		rotationKeys:        prev.RotationKeys,
		alsoKnownAs:         prev.AlsoKnownAs,
		services:            prev.Services,
	}
	for _, option := range options {
		option(&cfg)
	}
	prevLink, err := operationCID(prev)
	if err != nil {
		return nil, err
	}
	prevLinkStr := prevLink.String()
	return &Operation{
		Type:                OperationType,
		VerificationMethods: cfg.verificationMethods,
		RotationKeys:        cfg.rotationKeys,
		AlsoKnownAs:         cfg.alsoKnownAs,
		Services:            cfg.services,
		Previous:            &prevLinkStr,
	}, nil
}

// operationCID computes the CID of a signed operation, as used to link the next
// operation in the chain to its predecessor.
func operationCID(op *SignedOperation) (cid.Cid, error) {
	var opBytes bytes.Buffer
	if err := op.MarshalCBOR(&opBytes); err != nil {
		return cid.Undef, err
	}
	link, err := cid.V1Builder{
		Codec:  cid.DagCBOR,
		MhType: multihash.SHA2_256,
	}.Sum(opBytes.Bytes())
	if err != nil {
		return cid.Undef, fmt.Errorf("hashing previous operation: %w", err)
	}
	return link, nil
}

// NewTombstone creates a new PLC tombstone with the given previous operation
// CID. The tombstone indicates that the DID has been deactivated and should no
// longer be used.
func NewTombstone(prev cid.Cid) *Tombstone {
	return &Tombstone{
		Type:     TombstoneType,
		Previous: prev.String(),
	}
}

// NewTombstoneFromPreviousOperation creates a new PLC tombstone that deactivates
// the DID, linking to the given previous operation by its computed CID. It is a
// convenience over [NewTombstone] for the common case where you have fetched the
// last signed operation (e.g. via DirectoryClient.Last) rather than its CID.
func NewTombstoneFromPreviousOperation(prev *SignedOperation) (*Tombstone, error) {
	prevLink, err := operationCID(prev)
	if err != nil {
		return nil, err
	}
	return &Tombstone{
		Type:     TombstoneType,
		Previous: prevLink.String(),
	}, nil
}
