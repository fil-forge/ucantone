// Package cbordec provides a small generic helper for decoding CBOR bytes into
// a typed value, handling the pointer-type allocation that cbor-gen's
// pointer-receiver UnmarshalCBOR requires.
package cbordec

import (
	"bytes"
	"reflect"

	cbg "github.com/whyrusleeping/cbor-gen"
)

// Decode allocates T (if T is a pointer type) and decodes b into it. cbor-gen
// emits UnmarshalCBOR on pointer receivers, so a zero pointer T must be backed
// by an allocated value before it can be written into.
func Decode[T cbg.CBORUnmarshaler](b []byte) (T, error) {
	var v T
	if typ := reflect.TypeOf(v); typ != nil && typ.Kind() == reflect.Ptr {
		v = reflect.New(typ.Elem()).Interface().(T)
	}
	if err := v.UnmarshalCBOR(bytes.NewReader(b)); err != nil {
		var zero T
		return zero, err
	}
	return v, nil
}
