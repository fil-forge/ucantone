package policy_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/fil-forge/ucantone/ipld/datamodel"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	fdm "github.com/fil-forge/ucantone/ucan/delegation/policy/internal/fixtures/datamodel"
	"github.com/stretchr/testify/require"
)

func TestRoundtripCBOR(t *testing.T) {
	initial, err := policy.Build(policy.Equal(".foo", "bar"))
	require.NoError(t, err)
	var b bytes.Buffer
	err = initial.MarshalCBOR(&b)
	require.NoError(t, err)

	var decoded policy.Policy
	err = decoded.UnmarshalCBOR(&b)
	require.NoError(t, err)
	require.Len(t, decoded.Statements(), 1)
	require.Equal(t, policy.OpEqual, decoded.Statements()[0].Operator())
}

func TestParse(t *testing.T) {
	initial, err := policy.Parse(`[
		["==", ".foo", "bar"],
		["like", ".baz", "boz"]
	]`)
	require.NoError(t, err)
	require.Len(t, initial.Statements(), 2)
}

func TestFixtures(t *testing.T) {
	fixturesFile, err := os.Open("./internal/fixtures/policy.json")
	require.NoError(t, err)

	var fixtures fdm.FixturesModel
	err = fixtures.UnmarshalDagJSON(fixturesFile)
	require.NoError(t, err)

	for i, vector := range fixtures.Valid {
		for j, p := range vector.Policies {
			t.Run(fmt.Sprintf("valid %d policy %d", i, j), func(t *testing.T) {
				args := datamodel.Map{}
				err := args.UnmarshalDagJSON(bytes.NewReader(vector.Args.Raw))
				require.NoError(t, err)
				t.Logf("Args: %s\n", vector.Args.Raw)
				t.Logf("Policy: %s\n", p)

				match, err := policy.Match(p, args)
				require.NoError(t, err)
				require.True(t, match)
			})
		}
	}

	for i, vector := range fixtures.Invalid {
		for j, p := range vector.Policies {
			t.Run(fmt.Sprintf("invalid %d policy %d", i, j), func(t *testing.T) {
				args := datamodel.Map{}
				err := args.UnmarshalDagJSON(bytes.NewReader(vector.Args.Raw))
				require.NoError(t, err)
				t.Logf("Args: %s\n", vector.Args.Raw)
				t.Logf("Policy: %s\n", p)

				match, err := policy.Match(p, args)
				require.Error(t, err)
				t.Logf("Error: %s\n", err)
				require.False(t, match)
			})
		}
	}
}
