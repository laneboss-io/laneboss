package orghook

import (
	_ "embed"
	"encoding/json"
	"path/filepath"
	"strings"
)

type vendorLayout struct {
	Runner   string `json:"runner"`
	Home     string `json:"home"`
	Settings string `json:"settings"`
	Config   string `json:"config"`
}

//go:embed vendor-files.json
var vendorBytes []byte

var vendorLayouts = func() []vendorLayout {
	var layouts []vendorLayout
	if json.Unmarshal(vendorBytes, &layouts) != nil || len(layouts) == 0 {
		panic("invalid rendered vendor layout")
	}
	seen := map[string]bool{}
	for _, layout := range layouts {
		if layout.Runner == "" || seen[layout.Home] || !strings.HasPrefix(layout.Home, ".") {
			panic("invalid rendered vendor home")
		}
		for _, name := range []string{layout.Home, layout.Settings, layout.Config} {
			if name != "" && (name == "." || name == ".." || filepath.Base(name) != name) {
				panic("invalid rendered vendor path")
			}
		}
		seen[layout.Home] = true
	}
	return layouts
}()

func vendorFor(runner string) vendorLayout {
	for _, layout := range vendorLayouts {
		if layout.Runner == runner {
			return layout
		}
	}
	panic("unknown rendered vendor")
}

// VendorFiles is the renderer's ownership list, shared with org inspection.
func VendorFiles() map[string][]string {
	result := map[string][]string{}
	for _, layout := range vendorLayouts {
		result[layout.Home] = []string{layout.Settings}
		if layout.Config != "" {
			result[layout.Home] = append(result[layout.Home], layout.Config)
		}
	}
	return result
}
