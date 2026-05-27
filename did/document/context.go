package document

import (
	"encoding/json"
	"fmt"
)

const DidCoreContext = "https://www.w3.org/ns/did/v1.1"

// Context handles both string and []string formats for @context field
// as allowed by the DID Core specification
type Context []string

func (fc Context) MarshalJSON() ([]byte, error) {
	return json.Marshal(OneOrMany[string](append([]string{DidCoreContext}, fc...)))
}

func (fc *Context) UnmarshalJSON(data []byte) error {
	var ctxStrs OneOrMany[string]
	err := json.Unmarshal(data, &ctxStrs)
	if err != nil {
		return err
	}
	if len(ctxStrs) < 1 || ctxStrs[0] != DidCoreContext {
		return fmt.Errorf("@context must list %q first", DidCoreContext)
	}
	*fc = Context(ctxStrs[1:])
	return nil
}
