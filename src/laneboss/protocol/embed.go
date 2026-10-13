// Package protocol embeds the same protocol.md that the Python launcher ships.
package protocol

import (
	"bytes"
	_ "embed"
	"errors"
	"regexp"
)

//go:embed protocol.md
var text []byte

var versionLine = regexp.MustCompile(`(?m)^Protocol version: ([0-9]+\.[0-9]+\.[0-9]+)$`)

// Load returns the exact bytes and the version carried by those bytes.
// Returning a copy prevents a caller from changing the embedded protocol.
func Load() ([]byte, string, error) {
	match := versionLine.FindSubmatch(text)
	if match == nil {
		return nil, "", errors.New("the shipped protocol has no 'Protocol version: X.Y.Z' line")
	}
	return bytes.Clone(text), string(match[1]), nil
}
