package sqlite

import (
	"database/sql"
	"time"
)

func FormatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func ParseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}

func ParseNullTime(value sql.NullString) (time.Time, error) {
	if !value.Valid {
		return time.Time{}, nil
	}
	return ParseTime(value.String)
}
