package container_test

import (
	"testing"

	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/container"
	"github.com/fil-forge/ucantone/ucan/invocation"
	"github.com/stretchr/testify/require"
)

func TestContainer(t *testing.T) {
	codecs := []byte{
		container.Raw,
		container.Base64,
		container.Base64url,
		container.RawGzip,
		container.Base64Gzip,
		container.Base64urlGzip,
	}
	for _, code := range codecs {
		t.Run(container.FormatCodec(code)+" with invocation", func(t *testing.T) {
			issuer := testutil.RandomSigner(t)
			subject := testutil.RandomDID(t)
			command := testutil.Must(command.Parse("/test/invoke"))(t)
			arguments := testutil.RandomArgs(t)

			inv, err := invocation.Invoke(issuer, subject, command, arguments)
			require.NoError(t, err)

			initial := container.New(container.WithInvocations(inv))

			bytes, err := container.Encode(code, initial)
			require.NoError(t, err)

			decoded, err := container.Decode(bytes)
			require.NoError(t, err)
			require.Len(t, decoded.Invocations(), 1)
		})
	}
}
