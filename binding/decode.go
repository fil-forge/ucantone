package binding

import (
	"bytes"
	"reflect"

	cbg "github.com/whyrusleeping/cbor-gen"
)

// decode allocates T (if T is a pointer type) and decodes b into it. cbor-gen
// emits UnmarshalCBOR on pointer receivers, so a zero pointer T must be backed
// by an allocated value before it can be written into.
func decode[T cbg.CBORUnmarshaler](b []byte) (T, error) {
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
