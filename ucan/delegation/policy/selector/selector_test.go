package selector_test

import (
	"testing"

	"github.com/fil-forge/ucantone/ipld"
	"github.com/fil-forge/ucantone/ucan/delegation/policy/selector"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Run("identity", func(t *testing.T) {
		sel, err := selector.Parse(".")
		require.NoError(t, err)
		require.Equal(t, 1, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
	})

	t.Run("field", func(t *testing.T) {
		sel, err := selector.Parse(".foo")
		require.NoError(t, err)
		require.Equal(t, 1, len(sel))
		require.False(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Equal(t, sel[0].Field, "foo")
		require.Empty(t, sel[0].Index)
	})

	t.Run("explicit field", func(t *testing.T) {
		sel, err := selector.Parse(`.["foo"]`)
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.False(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Equal(t, sel[1].Field, "foo")
		require.Empty(t, sel[1].Index)
	})

	t.Run("index", func(t *testing.T) {
		sel, err := selector.Parse(".[138]")
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.False(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Equal(t, sel[1].Index, 138)
	})

	t.Run("negative index", func(t *testing.T) {
		sel, err := selector.Parse(".[-138]")
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.False(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Equal(t, sel[1].Index, -138)
	})

	t.Run("iterator", func(t *testing.T) {
		sel, err := selector.Parse(".[]")
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.False(t, sel[1].Optional)
		require.True(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Empty(t, sel[1].Index)
	})

	t.Run("optional field", func(t *testing.T) {
		sel, err := selector.Parse(".foo?")
		require.NoError(t, err)
		require.Equal(t, 1, len(sel))
		require.False(t, sel[0].Identity)
		require.True(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Equal(t, sel[0].Field, "foo")
		require.Empty(t, sel[0].Index)
	})

	t.Run("optional explicit field", func(t *testing.T) {
		sel, err := selector.Parse(`.["foo"]?`)
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.True(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Equal(t, sel[1].Field, "foo")
		require.Empty(t, sel[1].Index)
	})

	t.Run("optional index", func(t *testing.T) {
		sel, err := selector.Parse(".[138]?")
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.True(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Equal(t, sel[1].Index, 138)
	})

	t.Run("optional iterator", func(t *testing.T) {
		sel, err := selector.Parse(".[]?")
		require.NoError(t, err)
		require.Equal(t, 2, len(sel))
		require.True(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Empty(t, sel[0].Field)
		require.Empty(t, sel[0].Index)
		require.False(t, sel[1].Identity)
		require.True(t, sel[1].Optional)
		require.True(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Empty(t, sel[1].Index)
	})

	t.Run("nesting", func(t *testing.T) {
		str := `.foo.["bar"].[138]?.baz[1:]`
		sel, err := selector.Parse(str)
		require.NoError(t, err)
		printSegments(t, sel)
		require.Equal(t, str, sel.String())
		require.Equal(t, 7, len(sel))
		require.False(t, sel[0].Identity)
		require.False(t, sel[0].Optional)
		require.False(t, sel[0].Iterator)
		require.Empty(t, sel[0].Slice)
		require.Equal(t, sel[0].Field, "foo")
		require.Empty(t, sel[0].Index)
		require.True(t, sel[1].Identity)
		require.False(t, sel[1].Optional)
		require.False(t, sel[1].Iterator)
		require.Empty(t, sel[1].Slice)
		require.Empty(t, sel[1].Field)
		require.Empty(t, sel[1].Index)
		require.False(t, sel[2].Identity)
		require.False(t, sel[2].Optional)
		require.False(t, sel[2].Iterator)
		require.Empty(t, sel[2].Slice)
		require.Equal(t, sel[2].Field, "bar")
		require.Empty(t, sel[2].Index)
		require.True(t, sel[3].Identity)
		require.False(t, sel[3].Optional)
		require.False(t, sel[3].Iterator)
		require.Empty(t, sel[3].Slice)
		require.Empty(t, sel[3].Field)
		require.Empty(t, sel[3].Index)
		require.False(t, sel[4].Identity)
		require.True(t, sel[4].Optional)
		require.False(t, sel[4].Iterator)
		require.Empty(t, sel[4].Slice)
		require.Empty(t, sel[4].Field)
		require.Equal(t, sel[4].Index, 138)
		require.False(t, sel[5].Identity)
		require.False(t, sel[5].Optional)
		require.False(t, sel[5].Iterator)
		require.Empty(t, sel[5].Slice)
		require.Equal(t, sel[5].Field, "baz")
		require.Empty(t, sel[5].Index)
		require.False(t, sel[6].Identity)
		require.False(t, sel[6].Optional)
		require.False(t, sel[6].Iterator)
		require.Equal(t, sel[6].Slice, []int{1})
		require.Empty(t, sel[6].Field)
		require.Empty(t, sel[6].Index)
	})

	t.Run("non dotted", func(t *testing.T) {
		_, err := selector.Parse("foo")
		require.NotNil(t, err)
		t.Log(err)
	})

	t.Run("non quoted", func(t *testing.T) {
		_, err := selector.Parse(".[foo]")
		require.NotNil(t, err)
		t.Log(err)
	})
}

func printSegments(t *testing.T, s selector.Selector) {
	for i, seg := range s {
		t.Logf("%d: %s", i, seg.String())
	}
}

func TestSelect(t *testing.T) {
	var Name = func(first string, middle *string, last string) ipld.Map {
		m := map[string]any{
			"first": first,
			"last":  last,
		}
		if middle != nil {
			m["middle"] = *middle
		}
		return m
	}

	var Interest = func(name string, outdoor bool, experience int64) ipld.Map {
		return map[string]any{
			"name":       name,
			"outdoor":    outdoor,
			"experience": experience,
		}
	}

	var User = func(name ipld.Map, age int64, nationalities []string, interests []ipld.Map) ipld.Map {
		return map[string]any{
			"name":          name,
			"age":           age,
			"nationalities": nationalities,
			"interests":     nationalities,
		}
	}

	am := "Joan"
	alice := User(
		Name("Alice", &am, "Wonderland"),
		24,
		[]string{"British"},
		[]ipld.Map{
			Interest("Cycling", true, 4),
			Interest("Chess", false, 2),
		},
	)

	bob := User(
		Name("Bob", nil, "Builder"),
		35,
		[]string{"Canadian", "South African"},
		[]ipld.Map{
			Interest("Snowboarding", true, 8),
			Interest("Reading", false, 25),
		},
	)

	t.Run("identity", func(t *testing.T) {
		sel, err := selector.Parse(".")
		require.NoError(t, err)

		val, err := selector.Select(sel, alice)
		require.NoError(t, err)
		require.NotEmpty(t, val)

		user, ok := val.(ipld.Map)
		require.True(t, ok)
		require.Equal(t, alice, user)
	})

	t.Run("nested property", func(t *testing.T) {
		sel, err := selector.Parse(".name.first")
		require.NoError(t, err)

		val, err := selector.Select(sel, alice)
		require.NoError(t, err)
		require.NotEmpty(t, val)

		name, ok := val.(string)
		require.True(t, ok)
		require.Equal(t, "Alice", name)

		val, err = selector.Select(sel, bob)
		require.NoError(t, err)
		require.NotEmpty(t, val)

		name, ok = val.(string)
		require.True(t, ok)
		require.Equal(t, "Bob", name)
	})

	// t.Run("optional nested property", func(t *testing.T) {
	// 	sel, err := Parse(".name.middle?")
	// 	require.NoError(t, err)

	// 	one, many, err := Select(sel, anode)
	// 	require.NoError(t, err)
	// 	require.NotEmpty(t, one)
	// 	require.Empty(t, many)

	// 	fmt.Println(printer.Sprint(one))

	// 	name := must.String(one)
	// 	require.Equal(t, *alice.Name.Middle, name)

	// 	one, many, err = Select(sel, bnode)
	// 	require.NoError(t, err)
	// 	require.Empty(t, one)
	// 	require.Empty(t, many)
	// })

	// t.Run("not exists", func(t *testing.T) {
	// 	sel, err := Parse(".name.foo")
	// 	require.NoError(t, err)

	// 	one, many, err := Select(sel, anode)
	// 	require.Error(t, err)
	// 	require.Empty(t, one)
	// 	require.Empty(t, many)

	// 	fmt.Println(err)

	// 	if _, ok := err.(ResolutionError); !ok {
	// 		t.Fatalf("error was not a resolution error")
	// 	}
	// })

	// t.Run("optional not exists", func(t *testing.T) {
	// 	sel, err := Parse(".name.foo?")
	// 	require.NoError(t, err)

	// 	one, many, err := Select(sel, anode)
	// 	require.NoError(t, err)
	// 	require.Empty(t, one)
	// 	require.Empty(t, many)
	// })

	// t.Run("iterator", func(t *testing.T) {
	// 	sel, err := Parse(".interests[]")
	// 	require.NoError(t, err)

	// 	one, many, err := Select(sel, anode)
	// 	require.NoError(t, err)
	// 	require.Empty(t, one)
	// 	require.NotEmpty(t, many)

	// 	for _, n := range many {
	// 		fmt.Println(printer.Sprint(n))
	// 	}

	// 	iname := must.String(must.Node(many[0].LookupByString("name")))
	// 	require.Equal(t, alice.Interests[0].Name, iname)

	// 	iname = must.String(must.Node(many[1].LookupByString("name")))
	// 	require.Equal(t, alice.Interests[1].Name, iname)
	// })

	// t.Run("map iterator", func(t *testing.T) {
	// 	sel, err := Parse(".interests[0][]")
	// 	require.NoError(t, err)

	// 	one, many, err := Select(sel, anode)
	// 	require.NoError(t, err)
	// 	require.Empty(t, one)
	// 	require.NotEmpty(t, many)

	// 	for _, n := range many {
	// 		fmt.Println(printer.Sprint(n))
	// 	}

	// 	require.Equal(t, alice.Interests[0].Name, must.String(many[0]))
	// 	require.Equal(t, alice.Interests[0].Experience, int(must.Int(many[2])))
	// })
}
