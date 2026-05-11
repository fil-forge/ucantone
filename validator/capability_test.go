package validator_test

import (
	"strings"
	"testing"

	"github.com/fil-forge/ucantone/did"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan"
	"github.com/fil-forge/ucantone/ucan/command"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/fil-forge/ucantone/validator"
	"github.com/stretchr/testify/require"
)

func TestCapability(t *testing.T) {
	cap := validator.NewCapability(
		testutil.Must(did.Parse("did:example:alice"))(t),
	)

	t.Run("starts with the broadest capability", func(t *testing.T) {
		require.Equal(t, testutil.Must(did.Parse("did:example:alice"))(t), cap.Subject())
		require.Equal(t, command.Top(), cap.Command())
		require.Equal(t, policy.Policy{}, cap.Policy())
	})

	t.Run("can constrain its command:", func(t *testing.T) {
		for _, tcase := range []struct {
			cmds     []string
			expected string
			error    string
		}{
			{cmds: []string{"/widget"}, expected: "/widget"},
			{cmds: []string{"/widget/crank"}, expected: "/widget/crank"},
			{cmds: []string{"/widget", "/widget/crank"}, expected: "/widget/crank"},
			{cmds: []string{"/widget", "/widget"}, expected: "/widget"},
			{cmds: []string{"/widget/crank", "/widget"}, expected: "/widget/crank"},
			{cmds: []string{"/widget/crank", "/"}, expected: "/widget/crank"},
			{cmds: []string{"/widget", "/gadget"}, error: "cannot constrain to an unrelated command"},
		} {
			t.Run("/ + "+strings.Join(tcase.cmds, " + "), func(t *testing.T) {
				cap := cap

				var err error
				for _, cmd := range tcase.cmds {
					cap, err = cap.Constrain(
						testutil.Must(command.Parse(cmd))(t),
						policy.Policy{},
					)

					if err != nil {
						break
					}
				}

				if tcase.expected != "" {
					require.NoError(t, err)
					require.Equal(t, testutil.Must(command.Parse(tcase.expected))(t), cap.Command())
				} else {
					require.Error(t, err)
					require.Contains(t, err.Error(), tcase.error)
				}
			})
		}
	})

	t.Run("can constrain its policy", func(t *testing.T) {
		cap := cap

		cap, err := cap.Constrain(
			command.Top(),
			testutil.Must(policy.Build(
				policy.Equal(".widget.color", "green"),
			))(t),
		)
		require.NoError(t, err)
		require.Equal(t, []ucan.Statement{
			testutil.Must(policy.Equal(".widget.color", "green")())(t),
		}, cap.Policy().Statements())

		cap, err = cap.Constrain(
			command.Top(),
			testutil.Must(policy.Build(
				policy.GreaterThan(".widget.size", 3),
			))(t),
		)
		require.NoError(t, err)
		require.Equal(t, []ucan.Statement{
			testutil.Must(policy.Equal(".widget.color", "green")())(t),
			testutil.Must(policy.GreaterThan(".widget.size", 3)())(t),
		}, cap.Policy().Statements())
	})
}
