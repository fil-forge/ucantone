package did

import "fmt"

type UnsupportedMethodError struct {
	DID      DID
	Expected string
}

func (e UnsupportedMethodError) Error() string {
	return fmt.Sprintf("unsupported DID method in %s: expected %s", e.DID, e.Expected)
}

func ValidateMethod(d DID, expected string) error {
	if d.Method() != expected {
		return UnsupportedMethodError{
			DID:      d,
			Expected: expected,
		}
	}
	return nil
}
