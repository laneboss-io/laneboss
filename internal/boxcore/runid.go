package boxcore

import (
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// NewRunID combines a UTC timestamp with three random bytes in lower-case hex.
func NewRunID(now time.Time, rnd io.Reader) (string, error) {
	var b [3]byte
	if _, err := io.ReadFull(rnd, b[:]); err != nil {
		return "", fmt.Errorf("boxcore run id: %w", err)
	}
	return now.UTC().Format("20060102t150405") + "-" + hex.EncodeToString(b[:]), nil
}

// RunIDTail returns the last n characters, or the whole id when shorter.
func RunIDTail(id string, n int) string {
	if n <= 0 {
		return ""
	}
	chars := []rune(id)
	if len(chars) <= n {
		return id
	}
	return string(chars[len(chars)-n:])
}
