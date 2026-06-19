package did

import (
	"encoding/json"
	"net/url"
)

// URL is a wrapper around url.URL that implements json.Marshaler and
// json.Unmarshaler.
type URL struct {
	*url.URL
}

func ParseURL(s string) (URL, error) {
	parsed, err := url.Parse(s)
	if err != nil {
		return URL{}, err
	}
	return URL{URL: parsed}, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = parsed
	return nil
}

// MarshalJSON implements the json.Marshaler interface.
func (u URL) MarshalJSON() ([]byte, error) {
	if u.URL == nil {
		return json.Marshal(nil)
	}
	return json.Marshal(u.String())
}
