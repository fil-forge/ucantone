package document_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/fil-forge/ucantone/did/document"
	"github.com/stretchr/testify/require"
)

func TestDateTimeStamp(t *testing.T) {
	t.Run("to JSON", func(t *testing.T) {
		t.Run("marshals to a quoted RFC3339 string", func(t *testing.T) {
			d := document.DateTimeStamp(time.Date(2023, 1, 2, 15, 4, 5, 0, time.UTC))
			b, err := json.Marshal(d)
			require.NoError(t, err)
			require.JSONEq(t, `"2023-01-02T15:04:05Z"`, string(b))
		})

		t.Run("preserves timezone offset", func(t *testing.T) {
			loc := time.FixedZone("IST", 5*60*60+30*60)
			d := document.DateTimeStamp(time.Date(2023, 1, 2, 15, 4, 5, 0, loc))
			b, err := json.Marshal(d)
			require.NoError(t, err)
			require.JSONEq(t, `"2023-01-02T15:04:05+05:30"`, string(b))
		})
	})

	t.Run("from JSON", func(t *testing.T) {
		t.Run("unmarshals a valid RFC3339 string", func(t *testing.T) {
			var d document.DateTimeStamp
			err := json.Unmarshal([]byte(`"2023-01-02T15:04:05Z"`), &d)
			require.NoError(t, err)
			require.True(t, time.Date(2023, 1, 2, 15, 4, 5, 0, time.UTC).Equal(d.Time()))
		})

		t.Run("unmarshals a valid RFC3339 string with timezone offset", func(t *testing.T) {
			var d document.DateTimeStamp
			err := json.Unmarshal([]byte(`"2023-01-02T15:04:05+05:30"`), &d)
			require.NoError(t, err)
			loc := time.FixedZone("+0530", 5*60*60+30*60)
			require.True(t, time.Date(2023, 1, 2, 15, 4, 5, 0, loc).Equal(d.Time()))
		})

		t.Run("fails on a non-string JSON value", func(t *testing.T) {
			var d document.DateTimeStamp
			err := json.Unmarshal([]byte(`1234567890`), &d)
			require.Error(t, err)
		})

		t.Run("fails on a string that is not RFC3339", func(t *testing.T) {
			var d document.DateTimeStamp
			err := json.Unmarshal([]byte(`"not-a-date"`), &d)
			require.Error(t, err)
		})
	})
}

func TestDateTimeStamp_Time(t *testing.T) {
	t.Run("returns the underlying time.Time value", func(t *testing.T) {
		expected := time.Date(2023, 6, 15, 10, 30, 0, 0, time.UTC)
		d := document.DateTimeStamp(expected)
		require.Equal(t, expected, d.Time())
	})
}
