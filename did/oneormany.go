package did

import (
	"encoding/json"
	"errors"
)

type OneOrMany[T any] []T

func (om OneOrMany[T]) MarshalJSON() ([]byte, error) {
	if len(om) == 1 {
		return json.Marshal(om[0])
	}
	return json.Marshal([]T(om))
}

func (om *OneOrMany[T]) UnmarshalJSON(data []byte) error {
	var single T
	err := json.Unmarshal(data, &single)
	if err == nil {
		*om = OneOrMany[T]{single}
		return nil
	}
	var typeErr *json.UnmarshalTypeError
	if !errors.As(err, &typeErr) {
		return err
	}

	var multiple []T
	err = json.Unmarshal(data, &multiple)
	if err != nil {
		return err
	}

	*om = OneOrMany[T](multiple)
	return nil
}
