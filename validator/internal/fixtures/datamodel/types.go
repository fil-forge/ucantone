package datamodel

type ValidModel struct {
	Name        string   `dagjsongen:"name"`
	Description string   `dagjsongen:"description"`
	Invocation  []byte   `dagjsongen:"invocation"`
	Proofs      [][]byte `dagjsongen:"proofs"`
	Time        int64    `dagjsongen:"time"`
}

type ErrorModel struct {
	Name string `dagjsongen:"name"`
}

type InvalidModel struct {
	Name        string     `dagjsongen:"name"`
	Description string     `dagjsongen:"description"`
	Invocation  []byte     `dagjsongen:"invocation"`
	Proofs      [][]byte   `dagjsongen:"proofs"`
	Time        int64      `dagjsongen:"time"`
	Error       ErrorModel `dagjsongen:"error"`
}

type FixturesModel struct {
	Version  string         `dagjsongen:"version"`
	Comments string         `dagjsongen:"comments"`
	Valid    []ValidModel   `dagjsongen:"valid"`
	Invalid  []InvalidModel `dagjsongen:"invalid"`
}
