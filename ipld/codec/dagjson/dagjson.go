// Package dagjson exposes the multicodec identity and HTTP content-type for
// DAG-JSON. Marshaler/Unmarshaler interfaces live in [dag-json-gen] (jsg);
// import jsg directly when you need to constrain a type to be JSON-encodable.
//
// [dag-json-gen]: https://github.com/alanshaw/dag-json-gen
package dagjson

const (
	Code        = 0x0129
	ContentType = "application/vnd.ipld.dag-json"
)
