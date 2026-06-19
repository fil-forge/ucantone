package did

import "fmt"

type UnsupportedMethodError struct {
	DID    DID
	Reason string
}

func (e UnsupportedMethodError) Error() string {
	return fmt.Sprintf("unsupported DID method in %s: %s", e.DID, e.Reason)
}

func ValidateMethod(d DID, expected string) error {
	if d.Method() != expected {
		return UnsupportedMethodError{
			DID:    d,
			Reason: "expected " + expected,
		}
	}
	return nil
}
