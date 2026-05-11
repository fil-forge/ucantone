package datamodel

import (
	"bytes"
	"fmt"
	"io"

	cbg "github.com/whyrusleeping/cbor-gen"
)

// Raw is a CBOR-canonical opaque value backed by raw CBOR bytes.
//
// On the CBOR side it is a pure byte-passthrough (delegates to [cbg.Deferred]
// semantics) — decoded bytes are stored verbatim and re-emitted verbatim. This
// makes Raw suitable for envelope fields whose schema is determined at runtime
// by another field (e.g. UCAN args/meta determined by cmd) and removes the
// need to re-encode-then-re-decode in order to bind to a typed Go struct.
//
// On the dag-json side, Raw decodes the underlying CBOR via the [Any] machinery
// and emits dag-json (and inversely on Unmarshal). The dag-json path is for
// debug/inspection only — UCAN signing happens on CBOR bytes.
type Raw struct {
	cbor []byte
}

// NewRaw constructs a Raw from already-encoded CBOR bytes. The caller is
// responsible for ensuring the bytes are valid CBOR.
func NewRaw(cborBytes []byte) Raw {
	return Raw{cbor: cborBytes}
}

// Bytes returns the raw CBOR bytes. Typed callers should pass these to their
// own UnmarshalCBOR to bind directly into their schema.
func (r *Raw) Bytes() []byte {
	if r == nil {
		return nil
	}
	return r.cbor
}

func (r *Raw) MarshalCBOR(w io.Writer) error {
	if r == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	return (&cbg.Deferred{Raw: r.cbor}).MarshalCBOR(w)
}

func (r *Raw) UnmarshalCBOR(rd io.Reader) error {
	var d cbg.Deferred
	if err := d.UnmarshalCBOR(rd); err != nil {
		return err
	}
	if len(d.Raw) > 0 && d.Raw[0] != cbg.CborNull[0] {
		maj := d.Raw[0] >> 5
		if maj != cbg.MajMap {
			return fmt.Errorf("Raw: expected CBOR map, got major type %d", maj)
		}
	}
	r.cbor = d.Raw
	return nil
}

func (r *Raw) MarshalDagJSON(w io.Writer) error {
	if r == nil || r.cbor == nil {
		_, err := w.Write([]byte("null"))
		return err
	}
	var a Any
	if err := a.UnmarshalCBOR(bytes.NewReader(r.cbor)); err != nil {
		return fmt.Errorf("Raw: decoding CBOR for dag-json marshal: %w", err)
	}
	return a.MarshalDagJSON(w)
}

func (r *Raw) UnmarshalDagJSON(rd io.Reader) error {
	var a Any
	if err := a.UnmarshalDagJSON(rd); err != nil {
		return fmt.Errorf("Raw: decoding dag-json: %w", err)
	}
	var buf bytes.Buffer
	if err := a.MarshalCBOR(&buf); err != nil {
		return fmt.Errorf("Raw: re-encoding to CBOR: %w", err)
	}
	r.cbor = buf.Bytes()
	return nil
}
