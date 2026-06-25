package did

import (
	"encoding/json"
	"fmt"
)

const CoreContext = "https://www.w3.org/ns/did/v1.1"

// CoreContextV1 is the DID Core v1.0 context. It is accepted on input for
// interoperability with directories that have not adopted v1.1 (e.g. the PLC
// directory), but documents we produce always use [CoreContext] (v1.1).
const CoreContextV1 = "https://www.w3.org/ns/did/v1"

// Context handles both string and []string formats for @context field
// as allowed by the DID Core specification
type Context []string

func (fc Context) MarshalJSON() ([]byte, error) {
	return json.Marshal(OneOrMany[string](append([]string{CoreContext}, fc...)))
}

func (fc *Context) UnmarshalJSON(data []byte) error {
	var ctxStrs OneOrMany[string]
	err := json.Unmarshal(data, &ctxStrs)
	if err != nil {
		return err
	}
	if len(ctxStrs) < 1 || (ctxStrs[0] != CoreContext && ctxStrs[0] != CoreContextV1) {
		return fmt.Errorf("@context must list %q or %q first", CoreContext, CoreContextV1)
	}
	*fc = Context(ctxStrs[1:])
	return nil
}
