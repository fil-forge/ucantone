package policy_test

import (
	"testing"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/testutil"
	"github.com/fil-forge/ucantone/ucan/delegation/policy"
	"github.com/ipfs/go-cid"
	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	l0 := cid.MustParse("bafybeif4owy5gno5lwnixqm52rwqfodklf76hsetxdhffuxnplvijskzqq")
	l1 := cid.MustParse("bafkreifau35r7vi37tvbvfy3hdwvgb4tlflqf7zcdzeujqcjk3rsphiwte")

	testCases := []struct {
		name   string
		policy policy.StatementBuilderFunc
		value  any
		match  bool
	}{
		{
			name:   "comparison equal nil match",
			policy: policy.Equal(".", nil),
			value:  nil,
			match:  true,
		},
		{
			name:   "comparison equal nil no match",
			policy: policy.Equal(".", nil),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison equal nil in map match",
			policy: policy.Equal(".foo", nil),
			value:  map[string]ipld.Any{"foo": nil},
			match:  true,
		},
		{
			name:   "comparison equal nil in list match",
			policy: policy.Equal(".[0]", (*int)(nil)),
			value:  []*int{nil},
			match:  true,
		},
		{
			name:   "comparison equal string match",
			policy: policy.Equal(".", "test"),
			value:  "test",
			match:  true,
		},
		{
			name:   "comparison equal string no match",
			policy: policy.Equal(".", "test2"),
			value:  "test",
			match:  false,
		},
		{
			name:   "comparison equal string no match non-string",
			policy: policy.Equal(".", 138),
			value:  "test",
			match:  false,
		},
		{
			name:   "comparison equal int match",
			policy: policy.Equal(".", 138),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison equal int no match",
			policy: policy.Equal(".", 138),
			value:  1138,
			match:  false,
		},
		{
			name:   "comparison equal int no match non-int",
			policy: policy.Equal(".", "138"),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison equal bool match",
			policy: policy.Equal(".", true),
			value:  true,
			match:  true,
		},
		{
			name:   "comparison equal bool no match",
			policy: policy.Equal(".", true),
			value:  false,
			match:  false,
		},
		{
			name:   "comparison equal bool no match non-bool",
			policy: policy.Equal(".", "true"),
			value:  true,
			match:  false,
		},
		{
			name:   "comparison equal byte slice match",
			policy: policy.Equal(".", []byte{1, 2, 3}),
			value:  []byte{1, 2, 3},
			match:  true,
		},
		{
			name:   "comparison equal byte slice no match",
			policy: policy.Equal(".", []byte{1, 2, 3}),
			value:  []byte{4, 5, 6},
			match:  false,
		},
		{
			name:   "comparison equal byte slice no match non-byte slice",
			policy: policy.Equal(".", []byte{1, 2, 3}),
			value:  []string{"1", "2", "3"},
			match:  false,
		},
		{
			name:   "comparison equal string slice match",
			policy: policy.Equal(".", []string{"1", "2", "3"}),
			value:  []string{"1", "2", "3"},
			match:  true,
		},
		{
			name:   "comparison equal string slice no match",
			policy: policy.Equal(".", []string{"1", "2", "3"}),
			value:  []string{"4", "5", "6"},
			match:  false,
		},
		{
			name:   "comparison equal string slice no match non-string slice",
			policy: policy.Equal(".", []string{"1", "2", "3"}),
			value:  []byte{1, 2, 3},
			match:  false,
		},
		{
			name:   "comparison equal CID match",
			policy: policy.Equal(".", l0),
			value:  l0,
			match:  true,
		},
		{
			name:   "comparison equal CID no match",
			policy: policy.Equal(".", l1),
			value:  l0,
			match:  false,
		},
		{
			name:   "comparison equal CID no match non-CID",
			policy: policy.Equal(".", l0.String()),
			value:  l0,
			match:  false,
		},
		{
			name:   "comparison equal string in map match",
			policy: policy.Equal(".foo", "bar"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  true,
		},
		{
			name:   "comparison equal string in map match unambiguous field name",
			policy: policy.Equal(`.["foo"]`, "bar"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  true,
		},
		{
			name:   "comparison equal string in map no match",
			policy: policy.Equal(".foo", "baz"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  false,
		},
		{
			name:   "comparison equal string in map no match non-string",
			policy: policy.Equal(".foo", "baz"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  false,
		},
		{
			name:   "comparison equal string in map no match not found",
			policy: policy.Equal(".foobar", "baz"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  false,
		},
		{
			name:   "comparison equal string in list match",
			policy: policy.Equal(".[0]", "foo"),
			value:  []string{"foo"},
			match:  true,
		},
		{
			name:   "comparison equal string in list no match",
			policy: policy.Equal(".[0]", "bar"),
			value:  []string{"foo"},
			match:  false,
		},
		{
			name:   "comparison equal string in list no match non-string",
			policy: policy.Equal(".[0]", "bar"),
			value:  []int{138},
			match:  false,
		},
		{
			name:   "comparison equal string in list no match range error",
			policy: policy.Equal(".[1]", "foo"),
			value:  []string{"foo"},
			match:  false,
		},
		{
			name:   "comparison not equal nil match",
			policy: policy.NotEqual(".", nil),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison not equal nil no match",
			policy: policy.NotEqual(".", nil),
			value:  nil,
			match:  false,
		},
		{
			name:   "comparison not equal string match",
			policy: policy.NotEqual(".", "test"),
			value:  "test2",
			match:  true,
		},
		{
			name:   "comparison not equal string no match string",
			policy: policy.NotEqual(".", "test"),
			value:  "test",
			match:  false,
		},
		{
			name:   "comparison not equal int match",
			policy: policy.NotEqual(".", 138),
			value:  1138,
			match:  true,
		},
		{
			name:   "comparison not equal int no match",
			policy: policy.NotEqual(".", 138),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison not equal CID match",
			policy: policy.NotEqual(".", l0),
			value:  l1,
			match:  true,
		},
		{
			name:   "comparison not equal CID no match",
			policy: policy.NotEqual(".", l0),
			value:  l0,
			match:  false,
		},
		{
			name:   "comparison not equal string in map match",
			policy: policy.NotEqual(".foo", "baz"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  true,
		},
		{
			name:   "comparison not equal string in map match unambiguous field name",
			policy: policy.NotEqual(`.["foo"]`, "baz"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  true,
		},
		{
			name:   "comparison not equal string in map no match",
			policy: policy.NotEqual(".foo", "bar"),
			value:  map[string]ipld.Any{"foo": "bar"},
			match:  false,
		},
		{
			name:   "comparison not equal string in list match",
			policy: policy.NotEqual(".[0]", "bar"),
			value:  []string{"foo"},
			match:  true,
		},
		{
			name:   "comparison not equal string in list no match",
			policy: policy.NotEqual(".[0]", "foo"),
			value:  []string{"foo"},
			match:  false,
		},
		{
			name:   "comparison greater than int match",
			policy: policy.GreaterThan(".", 1),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison greater than int no match",
			policy: policy.GreaterThan(".", 138),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison greater than int no match non-int",
			policy: policy.GreaterThan(".", 138),
			value:  "138",
			match:  false,
		},
		{
			name:   "comparison greater than or equal int match",
			policy: policy.GreaterThanOrEqual(".", 138),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison greater than or equal int no match",
			policy: policy.GreaterThanOrEqual(".", 1138),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison greater than or equal int no match non-int",
			policy: policy.GreaterThanOrEqual(".", 138),
			value:  "138",
			match:  false,
		},
		{
			name:   "comparison less than int match",
			policy: policy.LessThan(".", 1138),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison less than int no match",
			policy: policy.LessThan(".", 138),
			value:  138,
			match:  false,
		},
		{
			name:   "comparison less than int no match non-int",
			policy: policy.LessThan(".", 138),
			value:  "138",
			match:  false,
		},
		{
			name:   "comparison less than or equal int match",
			policy: policy.LessThanOrEqual(".", 138),
			value:  138,
			match:  true,
		},
		{
			name:   "comparison less than or equal int no match",
			policy: policy.LessThanOrEqual(".", 138),
			value:  1138,
			match:  false,
		},
		{
			name:   "comparison less than or equal int no match non-int",
			policy: policy.LessThanOrEqual(".", 138),
			value:  "138",
			match:  false,
		},
		{
			name:   "negation match",
			policy: policy.Not(policy.Equal(".", true)),
			value:  false,
			match:  true,
		},
		{
			name:   "negation no match",
			policy: policy.Not(policy.Equal(".", false)),
			value:  false,
			match:  false,
		},
		{
			name: "conjunction match",
			policy: policy.And(
				policy.GreaterThan(".", 1),
				policy.LessThan(".", 1138),
			),
			value: 138,
			match: true,
		},
		{
			name:   "conjunction match no statements",
			policy: policy.And(),
			value:  138,
			match:  true,
		},
		{
			name: "conjunction no match",
			policy: policy.And(
				policy.GreaterThan(".", 1),
				policy.Equal(".", 1138),
			),
			value: 138,
			match: false,
		},
		{
			name: "disjunction match",
			policy: policy.Or(
				policy.GreaterThan(".", 1),
				policy.LessThan(".", 138),
			),
			value: 138,
			match: true,
		},
		{
			name: "disjunction no match",
			policy: policy.Or(
				policy.GreaterThan(".", 138),
				policy.Equal(".", 1138),
			),
			value: 138,
			match: false,
		},
		{
			name:   "wildcard match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob, Carol.",
			match:  true,
		},
		{
			name:   "wildcard match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob, Dan, Erin, Carol.",
			match:  true,
		},
		{
			name:   "wildcard match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob  , Carol.",
			match:  true,
		},
		{
			name:   "wildcard match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob*, Carol.",
			match:  true,
		},
		{
			name:   "wildcard no match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob, Carol",
			match:  false,
		},
		{
			name:   "wildcard no match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice*, Bob*, Carol!",
			match:  false,
		},
		{
			name:   "wildcard no match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  "Alice, Bob, Carol.",
			match:  false,
		},
		{
			name:   "wildcard no match",
			policy: policy.Like(".", `Alice\*, Bob*, Carol.`),
			value:  " Alice*, Bob, Carol. ",
			match:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pol := testutil.Must(policy.Build(tc.policy))(t)
			ok, err := policy.Match(pol, tc.value)
			if tc.match {
				require.NoError(t, err)
				require.True(t, ok)
			} else {
				require.Error(t, err)
				require.False(t, ok)
				t.Log(err)
			}
		})
	}

	// t.Run("quantification", func(t *testing.T) {
	// 	buildValueNode := func(v int64) ipld.Node {
	// 		np := basicnode.Prototype.Map
	// 		nb := np.NewBuilder()
	// 		ma, _ := nb.BeginMap(1)
	// 		ma.AssembleKey().AssignString("value")
	// 		ma.AssembleValue().AssignInt(v)
	// 		ma.Finish()
	// 		return nb.Build()
	// 	}

	// 	t.Run("all", func(t *testing.T) {
	// 		np := basicnode.Prototype.List
	// 		nb := np.NewBuilder()
	// 		la, _ := nb.BeginList(5)
	// 		la.AssembleValue().AssignNode(buildValueNode(5))
	// 		la.AssembleValue().AssignNode(buildValueNode(10))
	// 		la.AssembleValue().AssignNode(buildValueNode(20))
	// 		la.AssembleValue().AssignNode(buildValueNode(50))
	// 		la.AssembleValue().AssignNode(buildValueNode(100))
	// 		la.Finish()
	// 		nd := nb.Build()

	// 		pol := policy.Policy{
	// 			All(
	// 				mustParse(t, ".[]"),
	// 				GreaterThan(mustParse(t, ".value"), literal.Int(2)),
	// 			),
	// 		}
	// 		ok, err := policy.Match(pol, nd)
	// 		require.True(t, ok)

	// 		pol = policy.Policy{
	// 			All(
	// 				mustParse(t, ".[]"),
	// 				GreaterThan(mustParse(t, ".value"), literal.Int(20)),
	// 			),
	// 		}
	// 		ok, err = policy.Match(pol, nd)
	// 		require.False(t, ok)
	// 	})

	// 	t.Run("any", func(t *testing.T) {
	// 		np := basicnode.Prototype.List
	// 		nb := np.NewBuilder()
	// 		la, _ := nb.BeginList(5)
	// 		la.AssembleValue().AssignNode(buildValueNode(5))
	// 		la.AssembleValue().AssignNode(buildValueNode(10))
	// 		la.AssembleValue().AssignNode(buildValueNode(20))
	// 		la.AssembleValue().AssignNode(buildValueNode(50))
	// 		la.AssembleValue().AssignNode(buildValueNode(100))
	// 		la.Finish()
	// 		nd := nb.Build()

	// 		pol := policy.Policy{
	// 			Any(
	// 				mustParse(t, ".[]"),
	// 				GreaterThan(mustParse(t, ".value"), literal.Int(10)),
	// 				LessThan(mustParse(t, ".value"), literal.Int(50)),
	// 			),
	// 		}
	// 		ok, err := policy.Match(pol, nd)
	// 		require.True(t, ok)

	// 		pol = policy.Policy{
	// 			Any(
	// 				mustParse(t, ".[]"),
	// 				GreaterThan(mustParse(t, ".value"), literal.Int(100)),
	// 			),
	// 		}
	// 		ok, err = policy.Match(pol, nd)
	// 		require.False(t, ok)
	// 	})
	// })
}
