// Package dagcbor exposes the multicodec identity and HTTP content-type for
// DAG-CBOR. Marshaler/Unmarshaler interfaces live in [cbor-gen] (cbg);
// import cbg directly when you need to constrain a type to be CBOR-encodable.
//
// [cbor-gen]: https://github.com/whyrusleeping/cbor-gen
package dagcbor

const (
	Code        = 0x71
	ContentType = "application/vnd.ipld.dag-cbor"
)
