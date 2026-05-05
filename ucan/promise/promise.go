package promise

import (
	"errors"
	"io"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan"
	pdm "github.com/fil-forge/ucantone/ucan/promise/datamodel"
	"github.com/ipfs/go-cid"
)

const (
	AwaitAnyTag   = "await/*"
	AwaitOKTag    = "await/ok"
	AwaitErrorTag = "await/error"
)

type AwaitAny struct {
	Task ucan.Link
}

func (aa AwaitAny) MarshalCBOR(w io.Writer) error {
	m := datamodel.Map{AwaitAnyTag: aa.Task}
	return m.MarshalCBOR(w)
}

func (aa *AwaitAny) UnmarshalCBOR(r io.Reader) error {
	m := pdm.AwaitAnyModel{}
	if err := m.UnmarshalCBOR(r); err != nil {
		return err
	}
	if m.AwaitAny == cid.Undef {
		return errors.New("invalid promise")
	}
	*aa = AwaitAny{m.AwaitAny}
	return nil
}

func (aa AwaitAny) MarshalDagJSON(w io.Writer) error {
	m := datamodel.Map{AwaitAnyTag: aa.Task}
	return m.MarshalDagJSON(w)
}

func (aa *AwaitAny) UnmarshalDagJSON(r io.Reader) error {
	m := pdm.AwaitAnyModel{}
	if err := m.UnmarshalDagJSON(r); err != nil {
		return err
	}
	if m.AwaitAny == cid.Undef {
		return errors.New("invalid promise")
	}
	*aa = AwaitAny{m.AwaitAny}
	return nil
}

type AwaitOK struct {
	Task ucan.Link
}

func (ao AwaitOK) MarshalCBOR(w io.Writer) error {
	m := datamodel.Map{AwaitOKTag: ao.Task}
	return m.MarshalCBOR(w)
}

func (ao *AwaitOK) UnmarshalCBOR(r io.Reader) error {
	m := pdm.AwaitOKModel{}
	if err := m.UnmarshalCBOR(r); err != nil {
		return err
	}
	if m.AwaitOK == cid.Undef {
		return errors.New("invalid promise")
	}
	*ao = AwaitOK{m.AwaitOK}
	return nil
}

func (ao AwaitOK) MarshalDagJSON(w io.Writer) error {
	m := datamodel.Map{AwaitOKTag: ao.Task}
	return m.MarshalDagJSON(w)
}

func (ao *AwaitOK) UnmarshalDagJSON(r io.Reader) error {
	m := pdm.AwaitOKModel{}
	if err := m.UnmarshalDagJSON(r); err != nil {
		return err
	}
	if m.AwaitOK == cid.Undef {
		return errors.New("invalid promise")
	}
	*ao = AwaitOK{m.AwaitOK}
	return nil
}

type AwaitError struct {
	Task ucan.Link
}

func (ae AwaitError) MarshalCBOR(w io.Writer) error {
	m := datamodel.Map{AwaitErrorTag: ae.Task}
	return m.MarshalCBOR(w)
}

func (ae *AwaitError) UnmarshalCBOR(r io.Reader) error {
	m := pdm.AwaitErrorModel{}
	if err := m.UnmarshalCBOR(r); err != nil {
		return err
	}
	if m.AwaitError == cid.Undef {
		return errors.New("invalid promise")
	}
	*ae = AwaitError{m.AwaitError}
	return nil
}

func (ae AwaitError) MarshalDagJSON(w io.Writer) error {
	m := datamodel.Map{AwaitErrorTag: ae.Task}
	return m.MarshalDagJSON(w)
}

func (ae *AwaitError) UnmarshalDagJSON(r io.Reader) error {
	m := pdm.AwaitErrorModel{}
	if err := m.UnmarshalDagJSON(r); err != nil {
		return err
	}
	if m.AwaitError == cid.Undef {
		return errors.New("invalid promise")
	}
	*ae = AwaitError{m.AwaitError}
	return nil
}
