package crypto

import "log/slog"

type Sensitive []byte

func (s Sensitive) Zero() {
	for i := range s {
		s[i] = 0
	}
}

func (s Sensitive) String() string {
	return redacted
}

func (s Sensitive) GoString() string {
	return redacted
}

func (s Sensitive) LogValue() slog.Value {
	return slog.StringValue(redacted)
}

func (s Sensitive) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redacted + `"`), nil
}
