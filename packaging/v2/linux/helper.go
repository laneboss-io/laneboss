// Package linuxunit retains the installer template as the helper's policy source.
package linuxunit

import _ "embed"

//go:embed laneboss-helper.service.in
var helperTemplate string

// HelperTemplate returns the same bytes that the source installer renders.
func HelperTemplate() string { return helperTemplate }
