package result_test

import (
	"errors"
	"testing"

	"github.com/fil-forge/ucantone/result"
	"github.com/stretchr/testify/require"
)

func TestOK(t *testing.T) {
	r := result.OK[int, error](42)
	require.True(t, r.IsOk())
	require.False(t, r.IsErr())

	ok, errVal := r.Unpack()
	require.Equal(t, 42, ok)
	require.NoError(t, errVal)
}

func TestErr(t *testing.T) {
	boom := errors.New("boom")
	r := result.Err[int, error](boom)
	require.False(t, r.IsOk())
	require.True(t, r.IsErr())

	ok, errVal := r.Unpack()
	require.Equal(t, 0, ok) // zero value of O
	require.Same(t, boom, errVal)
}

func TestZeroValueBranchIsZero(t *testing.T) {
	t.Run("ok branch leaves err zero", func(t *testing.T) {
		r := result.OK[string, []byte]("hello")
		_, errBytes := r.Unpack()
		require.Nil(t, errBytes)
	})
	t.Run("err branch leaves ok zero", func(t *testing.T) {
		r := result.Err[string, []byte]([]byte("bad"))
		ok, _ := r.Unpack()
		require.Equal(t, "", ok)
	})
}
