package errors_test

import (
	"testing"

	"github.com/fil-forge/ucantone/errors"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Run("name and message", func(t *testing.T) {
		err := errors.New("MyError", "something went wrong")
		require.EqualError(t, err, "something went wrong")

		var named errors.Named
		require.True(t, errors.As(err, &named))
		require.Equal(t, "MyError", named.Name())
	})

	t.Run("formats message with args", func(t *testing.T) {
		err := errors.New("MyError", "value %d is not %s", 42, "valid")
		require.EqualError(t, err, "value 42 is not valid")
	})

	t.Run("no args leaves message untouched", func(t *testing.T) {
		err := errors.New("MyError", "100% literal: %s %d")
		require.EqualError(t, err, "100% literal: %s %d")
	})

	t.Run("returns a Named error", func(t *testing.T) {
		var err error = errors.New("Foo", "bar")
		named, ok := err.(errors.Named)
		require.True(t, ok)
		require.Equal(t, "Foo", named.Name())
	})
}
