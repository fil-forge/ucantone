package algorithm

type AlgorithmDef struct {
	Code    uint64
	Name    string
	Decoder func(input []byte) (Algorithm, int, error)
}

type Algorithm interface {
	Encode() ([]byte, error)
}
