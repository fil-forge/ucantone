package datamodel

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"sort"

	jsg "github.com/alanshaw/dag-json-gen"
	"github.com/fil-forge/ucantone/ipld"
	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// Map is a CBOR backed implementation of [ipld.Map]. Keys are strings and
// values may be any of the types supported by [ipld.Any].
type Map map[string]ipld.Any

func (mp Map) MarshalCBOR(w io.Writer) error {
	if mp == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	if err := cw.WriteMajorTypeHeader(cbg.MajMap, uint64(len(mp))); err != nil {
		return err
	}

	keys := slices.Collect(maps.Keys(mp))
	sort.Slice(keys, func(i, j int) bool {
		fi := keys[i]
		fj := keys[j]
		if len(fi) < len(fj) {
			return true
		}
		if len(fi) > len(fj) {
			return false
		}
		return fi < fj
	})

	for _, k := range keys {
		if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(k))); err != nil {
			return err
		}
		if _, err := cw.WriteString(k); err != nil {
			return err
		}

		v := Any{mp[k]}
		if err := v.MarshalCBOR(w); err != nil {
			return fmt.Errorf(`marshaling map value for key "%s": %w`, k, err)
		}
	}

	return nil
}

func (mp *Map) UnmarshalCBOR(r io.Reader) (err error) {
	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajMap {
		return fmt.Errorf("cbor input should be of type map")
	}

	if extra > cbg.MaxLength {
		return fmt.Errorf("Map: map struct too large (%d)", extra)
	}

	m := Map{}
	n := extra
	nameBuf := make([]byte, 2048)
	for range n {
		nameLen, ok, err := cbg.ReadFullStringIntoBuf(cr, nameBuf, 8192)
		if err != nil {
			return err
		}

		if !ok {
			if err := cbg.ScanForLinks(cr, func(cid.Cid) {}); err != nil {
				return err
			}
			continue
		}

		name := string(nameBuf[:nameLen])
		var a Any
		if err := a.UnmarshalCBOR(cr); err != nil {
			return fmt.Errorf(`unmarshaling map value for key "%s": %w`, name, err)
		}
		m[name] = a.Value
	}
	*mp = m

	return nil
}

func (mp Map) MarshalDagJSON(w io.Writer) error {
	jw := jsg.NewDagJsonWriter(w)
	if err := jw.WriteObjectOpen(); err != nil {
		return err
	}
	keys := slices.Collect(maps.Keys(mp))
	slices.Sort(keys)
	for i, k := range keys {
		if err := jw.WriteString(k); err != nil {
			return err
		}
		if err := jw.WriteObjectColon(); err != nil {
			return err
		}
		v := Any{mp[k]}
		if err := v.MarshalDagJSON(jw); err != nil {
			return err
		}
		if i < len(keys)-1 {
			if err := jw.WriteComma(); err != nil {
				return err
			}
		}
	}
	return jw.WriteObjectClose()
}

func (mp *Map) UnmarshalDagJSON(r io.Reader) error {
	jr := jsg.NewDagJsonReader(r)
	if err := jr.ReadObjectOpen(); err != nil {
		return err
	}
	close, err := jr.PeekObjectClose()
	if err != nil {
		return err
	}
	if close {
		if err := jr.ReadObjectClose(); err != nil {
			return err
		}
	} else {
		m := Map{}
		for i := range jsg.MaxLength {
			key, err := jr.ReadString(jsg.MaxLength)
			if err != nil {
				if errors.Is(err, jsg.ErrLimitExceeded) {
					return errors.New("IPLD map key too large")
				}
				return err
			}
			if err := jr.ReadObjectColon(); err != nil {
				return err
			}
			var a Any
			if err := a.UnmarshalDagJSON(jr); err != nil {
				return fmt.Errorf(`unmarshaling map value for key "%s": %w`, key, err)
			}
			m[key] = a.Value
			close, err := jr.ReadObjectCloseOrComma()
			if err != nil {
				return err
			}
			if close {
				break
			}
			if i == jsg.MaxLength-1 {
				return errors.New("IPLD map too large")
			}
		}
		*mp = m
	}
	return nil
}

var _ ipld.Map = (Map)(nil)
