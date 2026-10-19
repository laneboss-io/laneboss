package boxgcp

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

func (p *provider) harvestArgs(runID, dir string) []string {
	parts := []string{"gs://" + p.cfg.ResultsBucket}
	if prefix := strings.Trim(p.cfg.ObjectPrefix, "/"); prefix != "" {
		parts = append(parts, prefix)
	}
	parts = append(parts, runID, "out")
	// Only this call contains the brief's unverified rsync flag spelling.
	return []string{"storage", "rsync", "--recursive", strings.Join(parts, "/"), dir}
}

// FetchHarvest copies the run's output and counts only regular local files. A machine that still exists must
// pass the fence first; one that is gone leaves only the results bucket to read.
func (p *provider) FetchHarvest(ctx context.Context, b boxcore.Box, runID, dir string) (int, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, localError("fetch-harvest", "cannot create harvest directory", err)
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return 0, localError("fetch-harvest", "harvest root must be a directory", err)
	}
	if _, err := p.fence(ctx, b, "fetch-harvest"); err != nil && boxcore.KindOf(err) != boxcore.KindNotFound {
		return 0, err
	}
	result, err := p.invoke(ctx, "fetch-harvest", p.harvestArgs(runID, dir), p.cfg.Project)
	if strings.Contains(strings.ToLower(string(result.Stderr)), "no urls matched") ||
		strings.Contains(strings.ToLower(string(result.Stdout)), "no urls matched") {
		return 0, boxcore.NewError(boxcore.KindNotFound, "fetch-harvest", "", "no URLs matched", err)
	}
	if err != nil {
		return 0, err
	}
	count := 0
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return localError("fetch-harvest", "harvest contains a symbolic link", nil)
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return localError("fetch-harvest", "harvest contains a non-regular file", nil)
		}
		count++
		return nil
	})
	if err != nil {
		return 0, localError("fetch-harvest", "cannot count harvest files", err)
	}
	return count, nil
}
