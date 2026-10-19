package manifest

import (
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

// CopySelection rebases exactly the granted selection into an independent
// private directory. A file view uses one fixed leaf for its final file bind.
func CopySelection(source api.ObjectManifest, relative string) (api.ObjectManifest, string, error) {
	selected, err := Select(source, relative)
	if err != nil {
		return api.ObjectManifest{}, "", err
	}
	result := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{}}
	file := ""
	for _, entry := range selected {
		if relative != "." {
			if entry.Path == relative {
				if entry.Kind == "file" {
					entry.Path, file = "file", "file"
				} else {
					entry.Path = "."
				}
			} else {
				entry.Path = strings.TrimPrefix(entry.Path, relative+"/")
			}
		}
		if entry.Path == "." && entry.Kind == "directory" {
			entry.Mode = 0700
		}
		result.Entries = append(result.Entries, entry)
	}
	if err := Object(result); err != nil {
		return api.ObjectManifest{}, "", err
	}
	return result, file, nil
}
