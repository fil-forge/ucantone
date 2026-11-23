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
		// insecureOnly marks a URL only NewInsecure accepts.
		insecureOnly bool
	}{
		{url: "https://example.com", want: "did:web:example.com"},
		{url: "https://example.com/", want: "did:web:example.com"},
		{url: "https://Example.COM", want: "did:web:example.com"},
		{url: "https://example.com:443", want: "did:web:example.com"},
		{url: "https://example.com:3000", want: "did:web:example.com%3A3000"},
		{url: "https://example.com:80", want: "did:web:example.com%3A80"},
		{url: "https://example.com/user/alice", want: "did:web:example.com:user:alice"},
		{url: "https://example.com/user/alice/", want: "did:web:example.com:user:alice"},
		{url: "https://example.com:3000/user/alice", want: "did:web:example.com%3A3000:user:alice"},
		{url: "https://example.com/a:b", want: "did:web:example.com:a%3Ab"},
		{url: "https://example.com/a%20b", want: "did:web:example.com:a%20b"},
		{url: "https://example.com/~alice", want: "did:web:example.com:%7Ealice"},
		{url: "https://example.com/a@b+c=d", want: "did:web:example.com:a%40b%2Bc%3Dd"},
		{url: "https://example.com/caf%C3%A9", want: "did:web:example.com:caf%C3%A9"},
		{url: "https://example.com/did.json/alice", want: "did:web:example.com:did.json:alice"},
		{url: "http://example.com", want: "did:web:example.com", insecureOnly: true},
		{url: "http://example.com:80", want: "did:web:example.com", insecureOnly: true},
		{url: "http://example.com:443", want: "did:web:example.com%3A443", insecureOnly: true},
		{url: "http://piri-0:3000", want: "did:web:piri-0%3A3000", insecureOnly: true},
		{url: "https://example.com/user//alice", wantErr: "empty path segment"},
		{url: "https://example.com//user", wantErr: "empty path segment"},
		{url: "https://example.com/user//", wantErr: "empty path segment"},
		{url: "https://example.com//", wantErr: "empty path segment"},
		{url: "https://example.com/.well-known/did.json", wantErr: "URL of a DID document"},
		{url: "https://example.com/user/alice/did.json", wantErr: "URL of a DID document"},
		{url: "https://example.com/did.json", wantErr: "URL of a DID document"},
		{url: "https://ex%C3%A4mple.com", wantErr: "ASCII form"},
		{url: "https://example.com/?x=1", wantErr: "query"},
		{url: "https://example.com/#x", wantErr: "fragment"},
		{url: "https://user@example.com", wantErr: "user info"},
		{url: "https://[::1]:3000", wantErr: "not an IP address"},
		{url: "https://127.0.0.1:3000", wantErr: "not an IP address"},
		{url: "https://", wantErr: "no host"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			u, err := url.Parse(tt.url)
			require.NoError(t, err)

			if tt.wantErr != "" {
				_, err = web.New(*u)
				require.ErrorContains(t, err, tt.wantErr)
				_, err = web.NewInsecure(*u)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			got, err := web.NewInsecure(*u)
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())

			secure, err := web.New(*u)
			if tt.insecureOnly {
				require.ErrorContains(t, err, "must be an https URL")
			} else {
				require.NoError(t, err)
				require.Equal(t, got, secure)
			}

			// What New produces, Parse accepts.
			parsed, err := web.Parse(got.String())
			require.NoError(t, err)
			require.Equal(t, got, parsed)
		})
	}

	t.Run("an IP address is refused over http too", func(t *testing.T) {
		u, err := url.Parse("http://127.0.0.1:3000")
		require.NoError(t, err)

		_, err = web.NewInsecure(*u)
		require.ErrorContains(t, err, "not an IP address")
	})

	t.Run("a scheme that is neither http nor https is refused", func(t *testing.T) {
		for _, str := range []string{"ftp://example.com", "example.com"} {
			u, err := url.Parse(str)
			require.NoError(t, err)

			_, err = web.New(*u)
			require.ErrorContains(t, err, "must be an https URL")
			_, err = web.NewInsecure(*u)
			require.ErrorContains(t, err, "must be an http or https URL")
		}
	})
}

func TestParse(t *testing.T) {
	t.Run("accepts", func(t *testing.T) {
		for _, str := range []string{
			"did:web:example.com",
			"did:web:example.com%3A3000",
			"did:web:example.com%3a3000",
			"did:web:example.com:user:alice",
			"did:web:example.com%3A3000:user:alice",
			"did:web:localhost",
			"did:web:localhost%3A3000",
			"did:web:example.com:a%3Ab",
			"did:web:example.com:%7Ealice",
			"did:web:my_host.example-1.com",
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
		{str: "did:web:example.com:~alice", wantErr: "must be percent-encoded"},
		{str: "did:web:example.com:a@b", wantErr: "must be percent-encoded"},
		{str: "did:web:example.com:a b", wantErr: "must be percent-encoded"},
		{str: "did:web:ex~ample.com", wantErr: "must be percent-encoded"},
		{str: "did:web:ex%7Eample.com", wantErr: "not a host name"},
		{str: "did:web:example.com%3", wantErr: "not percent-encoded correctly"},
		{str: "did:web:example.com:user%zz", wantErr: "not percent-encoded correctly"},
		{str: "did:web:example.com%3Ahttp", wantErr: "not a port number"},
		{str: "did:web:example.com%3A", wantErr: "not a port number"},
		{str: "did:web:example.com%3A0", wantErr: "not a port number"},
		{str: "did:web:example.com%3A70000", wantErr: "not a port number"},
		{str: "did:web:example.com%3A80%3A90", wantErr: "not a port number"},
		{str: "did:web:user%40example.com", wantErr: "not a host name"},
		{str: "did:web:example.com%2Fuser", wantErr: "not a host name"},
		{str: "did:web:127.0.0.1", wantErr: "is an IP address"},
		{str: "did:web:127.0.0.1%3A3000", wantErr: "is an IP address"},
	}
	for _, tt := range rejects {
		t.Run("rejects "+tt.str, func(t *testing.T) {
			_, err := web.Parse(tt.str)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLocation(t *testing.T) {
	tests := []struct {
		did  string
		want string
	}{
		{did: "did:web:example.com", want: "https://example.com"},
		{did: "did:web:example.com%3A3000", want: "https://example.com:3000"},
		{did: "did:web:example.com%3a3000", want: "https://example.com:3000"},
		{did: "did:web:localhost%3A3000", want: "https://localhost:3000"},
		{did: "did:web:example.com:user:alice", want: "https://example.com/user/alice"},
		{did: "did:web:example.com%3A3000:user:alice", want: "https://example.com:3000/user/alice"},
		{did: "did:web:example.com:a%20b:c%3Ad", want: "https://example.com/a%20b/c%3Ad"},
		{did: "did:web:example.com:%7Ealice", want: "https://example.com/%7Ealice"},
	}
	for _, tt := range tests {
		t.Run(tt.did, func(t *testing.T) {
			got, err := web.Location(did.MustParse(tt.did))
			require.NoError(t, err)
			require.Equal(t, tt.want, got.String())
		})
	}

	t.Run("is the inverse of New", func(t *testing.T) {
		for _, str := range []string{
			"https://example.com",
			"https://example.com:3000",
			"https://example.com/user/alice",
			"https://example.com:3000/a%20b/c%3Ad",
		} {
			u, err := url.Parse(str)
			require.NoError(t, err)
			d, err := web.New(*u)
			require.NoError(t, err)

			got, err := web.Location(d)
			require.NoError(t, err)
			require.Equal(t, str, got.String())

			back, err := web.New(got)
			require.NoError(t, err)
			require.Equal(t, d, back)
		}
	})

	t.Run("the scheme can be set to http for a stack that serves over HTTP", func(t *testing.T) {
		got, err := web.Location(did.MustParse("did:web:piri-0%3A3000"))
		require.NoError(t, err)
		got.Scheme = "http"
		require.Equal(t, "http://piri-0:3000", got.String())
	})

	t.Run("refuses a DID that is not a well-formed did:web", func(t *testing.T) {
		_, err := web.Location(did.MustParse("did:plc:ewvi7nxzyoun6zhxrhs64oiz"))
		var umErr did.UnsupportedMethodError
		require.ErrorAs(t, err, &umErr)

		_, err = web.Location(did.MustParse("did:web:example.com%3Ahttp"))
		require.ErrorContains(t, err, "not a port number")

		_, err = web.Location(did.MustParse("did:web:127.0.0.1%3A3000"))
		require.ErrorContains(t, err, "is an IP address")
	})
}
