package datamodel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"reflect"
	"slices"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// Any is a CBOR backed implementation of the IPLD data model. Any supports
// serializing/deserializing the following kinds/types:
//
//   - Null (nil)
//   - Boolean (bool)
//   - Integer (int64, int)
//   - BigInteger (math/big) — encoded as a CBOR bignum: tag 2
//     for non-negative values and tag 3 for negative values (RFC 8949).
//   - String (string)
//   - Bytes ([]byte)
//   - List ([]Any)
//   - Map ([Map])
//   - Link ([cid.Cid])
//
// Map values and list items may be any of the above types.
type Any struct {
	Value any
}

// NewAny creates an CBOR backed IPLD data model type from the passed data. The
// following Go types are supported:
//
//   - nil
//   - bool
//   - int
//   - int64
//   - math/big.Int
//   - string
//   - []byte
//   - slice
//   - [Map]
//   - [cid.Cid]
//
// Using a value other than the above types will result in an error when the
// value is serialized to CBOR.
func NewAny(data ipld.Any) *Any {
	return &Any{Value: data}
}

func (a *Any) MarshalCBOR(w io.Writer) error {
	if a == nil || a.Value == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	switch v := a.Value.(type) {
	case Map:
		return v.MarshalCBOR(w)
	case ipld.Map:
		return Map(v).MarshalCBOR(w)
	case int64:
		return cbg.CborInt(v).MarshalCBOR(w)
	case int:
		return cbg.CborInt(v).MarshalCBOR(w)
	case big.Int:
		return marshalCborBigInt(w, &v)
	case *big.Int:
		return marshalCborBigInt(w, v)
	case bool:
		return cbg.CborBool(v).MarshalCBOR(w)
	case cid.Cid:
		return cbg.CborCid(v).MarshalCBOR(w)
	case string:
		cw := cbg.NewCborWriter(w)
		if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(v))); err != nil {
			return err
		}
		_, err := cw.WriteString(v)
		return err
	case []byte:
		cw := cbg.NewCborWriter(w)
		if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(v))); err != nil {
			return err
		}
		_, err := cw.Write(v)
		return err
	}

	rt := reflect.TypeOf(a.Value)
	switch rt.Kind() {
	// case reflect.Map:
	// 	if rt.Key().Kind() == reflect.String {
	// 		rv := reflect.ValueOf(a.Value)
	// 		m := make(Map, rv.Len())
	// 		for _, rk := range rv.MapKeys() {
	// 			m[rk.String()] = rv.MapIndex(rk).Interface()
	// 		}
	// 		if err := m.MarshalCBOR(w); err != nil {
	// 			return fmt.Errorf("marshaling map: %w", err)
	// 		}
	// 		return nil
	// 	}
	case reflect.Slice:
		cw := cbg.NewCborWriter(w)
		s := reflect.ValueOf(a.Value)
		if err := cw.WriteMajorTypeHeader(cbg.MajArray, uint64(s.Len())); err != nil {
			return err
		}
		for i := range s.Len() {
			a := Any{Value: s.Index(i).Interface()}
			if err := a.MarshalCBOR(w); err != nil {
				return fmt.Errorf("marshaling slice index: %d: %w", i, err)
			}
		}
		return nil
	}

	return fmt.Errorf("unsupported type: %T", a.Value)
}

func (a *Any) UnmarshalCBOR(r io.Reader) (err error) {
	*a = Any{}
	maj, extra, pr, err := peekCborHeader(r)
	if err != nil {
		return fmt.Errorf("peeking CBOR header: %w", err)
	}

	switch maj {
	case cbg.MajMap:
		m := Map{}
		if err = m.UnmarshalCBOR(pr); err != nil {
			return err
		}
		a.Value = map[string]ipld.Any(m)
		return nil
	case cbg.MajUnsignedInt, cbg.MajNegativeInt:
		var cbi cbg.CborInt
		if err = cbi.UnmarshalCBOR(pr); err != nil {
			return err
		}
		a.Value = int64(cbi)
		return nil
	case cbg.MajOther:
		switch extra {
		case 20:
			a.Value = false
			return nil
		case 21:
			a.Value = true
			return nil
		case 22: // null
			return nil
		}
	case cbg.MajTag:
		switch extra {
		case 2: // CBOR positive bignum (tag 2 + byte string): value = n
			b, err := readBignumBytes(pr)
			if err != nil {
				return err
			}
			a.Value = big.NewInt(0).SetBytes(b)
			return nil
		case 3: // CBOR negative bignum (tag 3 + byte string): value = -1 - n
			b, err := readBignumBytes(pr)
			if err != nil {
				return err
			}
			a.Value = big.NewInt(0).Sub(big.NewInt(-1), big.NewInt(0).SetBytes(b))
			return nil
		case 42:
			cbc := cbg.CborCid{}
			if err = cbc.UnmarshalCBOR(pr); err != nil {
				return err
			}
			a.Value = cid.Cid(cbc)
			return nil
		}
	case cbg.MajTextString:
		if extra > 0 {
			cr := cbg.NewCborReader(pr)
			str, err := cbg.ReadStringWithMax(cr, cbg.MaxLength)
			if err != nil {
				return err
			}
			a.Value = str
		} else {
			a.Value = ""
		}
		return nil
	case cbg.MajByteString:
		if extra > 0 {
			cr := cbg.NewCborReader(pr)
			bytes, err := cbg.ReadByteArray(cr, cbg.ByteArrayMaxLen)
			if err != nil {
				return err
			}
			a.Value = bytes
		} else {
			a.Value = []byte{}
		}
		return nil
	case cbg.MajArray:
		if extra > cbg.MaxLength {
			return fmt.Errorf("array too large (%d)", extra)
		}
		if extra > 0 {
			items := make([]any, 0, int(extra))
			var itemsType reflect.Type
			hasCommonType := true
			for range extra {
				item := Any{}
				if err := item.UnmarshalCBOR(r); err != nil {
					return err
				}
				items = append(items, item.Value)
				typ := reflect.TypeOf(item.Value)

				if hasCommonType {
					// first iteration (or all nil)
					if itemsType == nil {
						itemsType = typ
					} else if itemsType != typ {
						hasCommonType = false
						itemsType = nil
					}
				}
			}

			// if all items have the same type and the type is not nil, create a typed slice
			if hasCommonType && itemsType != nil {
				sliceType := reflect.SliceOf(itemsType)
				sliceValue := reflect.MakeSlice(sliceType, len(items), len(items))
				for i, v := range items {
					sliceValue.Index(i).Set(reflect.ValueOf(v))
				}
				a.Value = sliceValue.Interface()
			} else {
				a.Value = items
			}
		} else {
			a.Value = []any{}
		}
		return nil
	}

	return fmt.Errorf("unsupported CBOR type: %d", maj)
}

func (a *Any) MarshalDagJSON(w io.Writer) error {
	jw := jsg.NewDagJsonWriter(w)
	if a == nil || a.Value == nil {
		return jw.WriteNull()
	}
	switch v := a.Value.(type) {
	case Map:
		return v.MarshalDagJSON(w)
	case ipld.Map:
		return Map(v).MarshalDagJSON(w)
	case int64:
		return jw.WriteInt64(v)
	case int:
		return jw.WriteInt64(int64(v))
	case big.Int:
		return jw.WriteBigInt(&v)
	case *big.Int:
		if v == nil {
			return jw.WriteNull()
		}
		return jw.WriteBigInt(v)
	case bool:
		return jw.WriteBool(v)
	case cid.Cid:
		return jw.WriteCid(v)
	case string:
		return jw.WriteString(v)
	case []byte:
		return jw.WriteBytes(v)
	}

	rt := reflect.TypeOf(a.Value)
	switch rt.Kind() {
	// case reflect.Map:
	// 	if rt.Key().Kind() == reflect.String {
	// 		rv := reflect.ValueOf(a.Value)
	// 		m := make(Map, rv.Len())
	// 		for _, rk := range rv.MapKeys() {
	// 			m[rk.String()] = rv.MapIndex(rk).Interface()
	// 		}
	// 		if err := m.MarshalDagJSON(w); err != nil {
	// 			return fmt.Errorf("marshaling map: %w", err)
	// 		}
	// 		return nil
	// 	}
	case reflect.Slice:
		if err := jw.WriteArrayOpen(); err != nil {
			return err
		}
		s := reflect.ValueOf(a.Value)
		for i := range s.Len() {
			a := Any{Value: s.Index(i).Interface()}
			if err := a.MarshalDagJSON(w); err != nil {
				return fmt.Errorf("marshaling slice index: %d: %w", i, err)
			}
			if i < s.Len()-1 {
				if err := jw.WriteComma(); err != nil {
					return err
				}
			}
		}
		return jw.WriteArrayClose()
	}

	return fmt.Errorf("unsupported type: %T", a.Value)
}

func (a *Any) UnmarshalDagJSON(r io.Reader) (err error) {
	*a = Any{}
	jr := jsg.NewDagJsonReader(r)
	t, err := jr.PeekType()
	if err != nil {
		return err
	}
	switch t {
	case "null":
		return jr.ReadNull()
	case "boolean":
		v, err := jr.ReadBool()
		if err != nil {
			return err
		}
		a.Value = v
	case "string":
		v, err := jr.ReadString(jsg.MaxLength)
		if err != nil {
			return err
		}
		a.Value = v
	case "number":
		v, err := jr.ReadNumberAsBigInt(jsg.MaxLength)
		if err != nil {
			return err
		}
		// There's no distinction in JSON between int64 and big.Int, there is just
		// number. If the value fits in an int64, return it as an int64. It means
		// we can't round trip a big.Int that fits in an int64, but there is not
		// really a good alternative here without inventing our own encoding for
		// big.Int in JSON. If you need to round trip, use dag-json-gen to generate
		// your encoders/decoders or use string or bytes or your own type instead.
		if v.IsInt64() {
			a.Value = v.Int64()
		} else {
			a.Value = v
		}
	case "array":
		if err := jr.ReadArrayOpen(); err != nil {
			return err
		}
		close, err := jr.PeekArrayClose()
		if err != nil {
			return err
		}
		if close {
			if err := jr.ReadArrayClose(); err != nil {
				return err
			}
			a.Value = []any{}
		} else {
			items := []any{}
			var itemsType reflect.Type
			hasCommonType := true
			for i := range jsg.MaxLength {
				item := Any{}
				if err := item.UnmarshalDagJSON(jr); err != nil {
					return err
				}
				items = append(items, item.Value)
				typ := reflect.TypeOf(item.Value)

				if hasCommonType {
					// first iteration (or all nil)
					if itemsType == nil {
						itemsType = typ
					} else if itemsType != typ {
						hasCommonType = false
						itemsType = nil
					}
				}

				close, err := jr.ReadArrayCloseOrComma()
				if err != nil {
					return err
				}
				if close {
					break
				}
				if i == jsg.MaxLength-1 {
					return errors.New("IPLD array too large")
				}
			}

			// if all items have the same type and the type is not nil, create a typed slice
			if hasCommonType && itemsType != nil {
				sliceType := reflect.SliceOf(itemsType)
				sliceValue := reflect.MakeSlice(sliceType, len(items), len(items))
				for i, v := range items {
					sliceValue.Index(i).Set(reflect.ValueOf(v))
				}
				a.Value = sliceValue.Interface()
			} else {
				a.Value = items
			}
		}
	case "object":
		m := Map{}
		if err := m.UnmarshalDagJSON(jr); err != nil {
			return err
		}
		keys := slices.Collect(maps.Keys(m))
		if len(keys) == 1 && keys[0] == "/" {
			switch v := m["/"].(type) {
			case string:
				c, err := cid.Parse(v)
				if err != nil {
					return err
				}
				a.Value = c
			case map[string]ipld.Any:
				skeys := slices.Collect(maps.Keys(v))
				if len(skeys) == 1 && skeys[0] == "bytes" {
					switch bv := v["bytes"].(type) {
					case string:
						decoded, err := base64.RawStdEncoding.DecodeString(bv)
						if err != nil {
							return err
						}
						a.Value = decoded
					default:
						a.Value = map[string]ipld.Any(m)
					}
				} else {
					a.Value = map[string]ipld.Any(m)
				}
			default:
				a.Value = map[string]ipld.Any(m)
			}
		} else {
			a.Value = map[string]ipld.Any(m)
		}
	}
	return nil
}

// marshalCborBigInt writes a [big.Int] as a CBOR bignum (RFC 8949): tag 2 for
// non-negative values and tag 3 for negative values, each followed by a byte
// string holding the big-endian magnitude. A negative value v is encoded as
// the magnitude of n = -1 - v, so it round-trips via value = -1 - n on decode.
func marshalCborBigInt(w io.Writer, v *big.Int) error {
	if v == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}
	tag := uint64(2)
	mag := v // non-negative: encode the magnitude directly
	if v.Sign() < 0 {
		tag = 3
		mag = big.NewInt(0).Sub(big.NewInt(-1), v) // n = -1 - v
	}
	cw := cbg.NewCborWriter(w)
	if err := cw.WriteMajorTypeHeader(cbg.MajTag, tag); err != nil {
		return err
	}
	b := mag.Bytes() // raw big-endian magnitude (no sign prefix)
	if err := cw.WriteMajorTypeHeader(cbg.MajByteString, uint64(len(b))); err != nil {
		return err
	}
	_, err := cw.Write(b)
	return err
}

// readBignumBytes consumes a CBOR bignum tag header and returns the bytes of
// the following byte string (the big-endian magnitude).
func readBignumBytes(r io.Reader) ([]byte, error) {
	cr := cbg.NewCborReader(r)
	if _, _, err := cr.ReadHeader(); err != nil { // consume the bignum tag header
		return nil, err
	}
	return cbg.ReadByteArray(cr, 256)
}

func peekCborHeader(r io.Reader) (byte, uint64, io.Reader, error) {
	cr := cbg.NewCborReader(r)
	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return 0, 0, nil, err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()
	// TODO: find a better way of doing this
	var headerBuf bytes.Buffer
	cw := cbg.NewCborWriter(&headerBuf)
	err = cw.CborWriteHeader(maj, extra)
	if err != nil {
		return 0, 0, nil, err
	}
	return maj, extra, io.MultiReader(&headerBuf, r), nil
}
