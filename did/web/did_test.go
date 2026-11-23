package web_test

import (
	"net/url"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/did/web"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		url     string
		want    string
		wantErr string
	}{
		{url: "https://example.com", want: "did:web:example.com"},
		{url: "https://example.com/", want: "did:web:example.com"},
		{url: "https://Example.COM", want: "did:web:example.com"},
		{url: "https://example.com:443", want: "did:web:example.com"},
		{url: "https://example.com:3000", want: "did:web:example.com%3A3000"},
		{url: "http://example.com", want: "did:web:example.com"},
		{url: "http://example.com:80", want: "did:web:example.com"},
		{url: "http://example.com:443", want: "did:web:example.com%3A443"},
		{url: "http://127.0.0.1:3000", want: "did:web:127.0.0.1%3A3000"},
		{url: "https://example.com/user/alice", want: "did:web:example.com:user:alice"},
		{url: "https://example.com/user/alice/", want: "did:web:example.com:user:alice"},
		{url: "https://example.com:3000/user/alice", want: "did:web:example.com%3A3000:user:alice"},
		{url: "https://example.com/a:b", want: "did:web:example.com:a%3Ab"},
		{url: "https://example.com/a%20b", want: "did:web:example.com:a%20b"},
		{url: "https://example.com/user//alice", wantErr: "empty path segment"},
		{url: "https://example.com/?x=1", wantErr: "query"},
		{url: "https://example.com/#x", wantErr: "fragment"},
		{url: "https://user@example.com", wantErr: "user info"},
		{url: "ftp://example.com", wantErr: "http or https"},
		{url: "example.com", wantErr: "http or https"},
		{url: "https://[::1]:3000", wantErr: "IPv6"},
		{url: "https://", wantErr: "no host"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			got, err := web.New(*u)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())

			// What New produces, Parse accepts.
			parsed, err := web.Parse(got.String())
			require.NoError(t, err)
			require.Equal(t, got, parsed)
		})
	}
}

func TestParse(t *testing.T) {
	t.Run("accepts", func(t *testing.T) {
		for _, str := range []string{
			"did:web:example.com",
			"did:web:example.com%3A3000",
			"did:web:example.com%3a3000",
			"did:web:example.com:user:alice",
			"did:web:example.com%3A3000:user:alice",
			"did:web:127.0.0.1%3A3000",
			"did:web:localhost",
			"did:web:example.com:a%3Ab",
		} {
			t.Run(str, func(t *testing.T) {
				d, err := web.Parse(str)
				require.NoError(t, err)
				require.Equal(t, web.Method, d.Method())
				require.Equal(t, str, d.String())
			})
		}
	})

	t.Run("rejects a missing did prefix", func(t *testing.T) {
		_, err := web.Parse("web:example.com")
		require.Error(t, err)
	})

	t.Run("rejects a non-web method", func(t *testing.T) {
		_, err := web.Parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
		var umErr did.UnsupportedMethodError
		require.ErrorAs(t, err, &umErr)
	})

	rejects := []struct {
		str     string
		wantErr string
	}{
		{str: "did:web:", wantErr: "no host"},
		{str: "did:web::user", wantErr: "no host"},
		{str: "did:web:%3A3000", wantErr: "no host"},
		{str: "did:web:example.com:", wantErr: "empty path segment"},
		{str: "did:web:example.com::alice", wantErr: "empty path segment"},
		{str: "did:web:example.com/user", wantErr: "must be percent-encoded"},
		{str: "did:web:example.com?x=1", wantErr: "must be percent-encoded"},
		{str: "did:web:example.com#key-0", wantErr: "must be percent-encoded"},
		{str: "did:web:example.com%3", wantErr: "not percent-encoded correctly"},
		{str: "did:web:example.com:user%zz", wantErr: "not percent-encoded correctly"},
		{str: "did:web:example.com%3Ahttp", wantErr: "not a port number"},
		{str: "did:web:example.com%3A", wantErr: "not a port number"},
		{str: "did:web:example.com%3A0", wantErr: "not a port number"},
		{str: "did:web:example.com%3A70000", wantErr: "not a port number"},
		{str: "did:web:example.com%3A80%3A90", wantErr: "not a port number"},
		{str: "did:web:user%40example.com", wantErr: "not a host name"},
	}
	for _, tt := range rejects {
		t.Run("rejects "+tt.str, func(t *testing.T) {
			_, err := web.Parse(tt.str)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
