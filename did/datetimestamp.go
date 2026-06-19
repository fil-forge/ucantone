package did

import (
	"encoding/json"
	"time"
)

type DateTimeStamp time.Time

func (d DateTimeStamp) Time() time.Time {
	return time.Time(d)
}

func (d DateTimeStamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Time().Format(time.RFC3339))
}

func (d *DateTimeStamp) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return err
	}

	*d = DateTimeStamp(t)
	return nil
}
