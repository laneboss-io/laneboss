package boxcore

import (
	"regexp"
	"strconv"
	"time"
)

// FormatUTC formats a time in UTC with whole seconds and a Z suffix.
func FormatUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// NormalizeUTC reads and validates the first timestamp, ignoring its suffix.
func NormalizeUTC(text string) (string, bool) {
	re := regexp.MustCompile(`(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})`)
	match := re.FindStringSubmatch(text)
	if match == nil {
		return "", false
	}
	var fields [6]int
	for i := range fields {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return "", false
		}
		fields[i] = n
	}
	t := time.Date(fields[0], time.Month(fields[1]), fields[2], fields[3], fields[4], fields[5], 0, time.UTC)
	if t.Year() != fields[0] || int(t.Month()) != fields[1] || t.Day() != fields[2] ||
		t.Hour() != fields[3] || t.Minute() != fields[4] || t.Second() != fields[5] {
		return "", false
	}
	return FormatUTC(t), true
}

// SecondsBetween returns signed whole seconds between two valid timestamps.
func SecondsBetween(startUTC, endUTC string) (int, bool) {
	start, ok := NormalizeUTC(startUTC)
	if !ok {
		return 0, false
	}
	end, ok := NormalizeUTC(endUTC)
	if !ok {
		return 0, false
	}
	a, err := time.Parse("2006-01-02T15:04:05Z", start)
	if err != nil {
		return 0, false
	}
	b, err := time.Parse("2006-01-02T15:04:05Z", end)
	if err != nil {
		return 0, false
	}
	// Unix seconds avoid time.Duration saturation over long date ranges.
	return int(b.Unix() - a.Unix()), true
}
