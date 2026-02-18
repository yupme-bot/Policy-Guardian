package timefmt

import (
	"errors"
	"time"
)

const Layout = "2006-01-02T15:04:05Z"

func NowUTC() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func Format(t time.Time) string {
	return t.UTC().Truncate(time.Second).Format(Layout)
}

func Parse(s string) (time.Time, error) {
	t, err := time.Parse(Layout, s)
	if err != nil {
		return time.Time{}, err
	}
	if Format(t) != s {
		return time.Time{}, errors.New("invalid timestamp format")
	}
	return t.UTC(), nil
}
