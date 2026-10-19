//go:build linux

package admin

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func nativeGitOptions() []string {
	return []string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "safe.directory=", "-c", "submodule.recurse=false", "-c", "diff.ignoreSubmodules=all", "-c", "status.submoduleSummary=false",
		"-c", "core.attributesFile=/dev/null", "-c", "core.untrackedCache=false", "-c", "protocol.allow=never", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "-c", "core.logAllRefUpdates=false"}
}

// Reserve a conservative upper bound before creating a snapshot or Git object.
// Each entry is charged for names, both indexes, tree records and loose-object
// framing. Six payload copies cover work + snapshot + worst-case deflate output
// and a complete retry temporary object. No attributes/filters transform bytes.
func workspaceImportCharge(manifest api.ObjectManifest, ceiling uint64) (uint64, error) {
	var total uint64
	add := func(n uint64) error {
		if n > ceiling-total {
			return failure(api.CodeBudget, "native workspace import exceeds its reserved byte quota")
		}
		total += n
		return nil
	}
	if err := add(128 << 10); err != nil {
		return 0, err
	}
	for name, entry := range dataExpected(manifest) {
		if err := add(8192 + uint64(len(name))*8); err != nil {
			return 0, err
		}
		size := uint64(dataSize(entry))
		if entry.Kind == "symlink" {
			size = uint64(len(entry.LinkTarget))
		}
		for range 6 {
			if err := add(size); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func workspaceSnapshot(ctx context.Context, repository, work *os.File, manifest api.ObjectManifest) (*os.File, error) {
	snapshot, err := dataDirectory(repository, "snapshot")
	if err != nil {
		return nil, err
	}
	if err := dataEmpty(snapshot); err == nil {
		if err := dataStage(ctx, work, snapshot, manifest, 0, 0); err != nil {
			snapshot.Close()
			return nil, err
		}
	} else if err := dataVerify(ctx, snapshot, manifest, 0, 0); err != nil {
		snapshot.Close()
		return nil, failure(api.CodeIntegrity, "retained root-owned import snapshot differs from its measured manifest")
	}
	if err := dataVerify(ctx, snapshot, manifest, 0, 0); err != nil {
		snapshot.Close()
		return nil, err
	}
	return snapshot, nil
}

// No Git command traverses the lane tree during import. Only bytes streamed
// from the descriptor-verified, helper-owned snapshot enter hash-object, and
// only constructed tree records enter mktree. Git's own result is compared
// with the independent object digest; no config, attributes or gitlink import.
func importWorkspaceTree(ctx context.Context, e cleanupEnrollment, snapshot *os.File, manifest api.ObjectManifest, live func() error) (string, error) {
	entries := dataExpected(manifest)
	var tree func(string) (string, bool, error)
	tree = func(directory string) (string, bool, error) {
		names := []string{}
		for name := range entries {
			if name != "." && path.Dir(name) == directory {
				names = append(names, name)
			}
		}
		sort.Slice(names, func(i, j int) bool {
			a, b := path.Base(names[i]), path.Base(names[j])
			if entries[names[i]].Kind == "directory" {
				a += "/"
			}
			if entries[names[j]].Kind == "directory" {
				b += "/"
			}
			return a < b
		})
		var records, binary bytes.Buffer
		for _, name := range names {
			entry := entries[name]
			mode, kind, oid := "100644", "blob", ""
			if entry.Kind == "directory" {
				child, present, err := tree(name)
				if err != nil {
					return "", false, err
				}
				if !present {
					continue
				} // Git has no empty-directory index entries.
				mode, kind, oid = "40000", "tree", child
			} else {
				var reader io.Reader
				var file *os.File
				size := dataSize(entry)
				if entry.Kind == "symlink" {
					mode, reader, size = "120000", strings.NewReader(entry.LinkTarget), int64(len(entry.LinkTarget))
				} else if entry.Kind == "file" {
					if entry.Mode&0111 != 0 {
						mode = "100755"
					}
					var err error
					file, err = dataFile(snapshot, name, false)
					if err != nil {
						return "", false, err
					}
					reader = file
				} else {
					return "", false, failure(api.CodeIntegrity, "unsupported native import entry or gitlink")
				}
				digest := sha1.New()
				fmt.Fprintf(digest, "blob %d\x00", size)
				limited := &io.LimitedReader{R: dataReader{ctx, reader}, N: size + 1}
				raw, err := workspaceGitInput(ctx, e, live, io.TeeReader(limited, digest), "--git-dir="+e.Repository, "hash-object", "--no-filters", "-w", "--stdin")
				if file != nil {
					err = errors.Join(err, file.Close())
				}
				oid = strings.TrimSpace(string(raw))
				if err != nil {
					return "", false, err
				}
				if limited.N != 1 || oid != hex.EncodeToString(digest.Sum(nil)) {
					return "", false, failure(api.CodeIntegrity, "native Git blob differs from its immutable snapshot bytes")
				}
			}
			decoded, err := hex.DecodeString(oid)
			if err != nil || len(decoded) != 20 {
				return "", false, failure(api.CodeIntegrity, "native import returned a malformed object")
			}
			fmt.Fprintf(&records, "%s %s %s\t%s%c", mode, kind, oid, path.Base(name), 0)
			fmt.Fprintf(&binary, "%s %s%c", mode, path.Base(name), 0)
			binary.Write(decoded)
		}
		digest := sha1.New()
		io.WriteString(digest, "tree "+strconv.Itoa(binary.Len())+"\x00")
		digest.Write(binary.Bytes())
		raw, err := workspaceGitInput(ctx, e, live, &records, "--git-dir="+e.Repository, "mktree", "-z")
		if err != nil {
			return "", false, err
		}
		oid := strings.TrimSpace(string(raw))
		if oid != hex.EncodeToString(digest.Sum(nil)) {
			return "", false, failure(api.CodeIntegrity, "native Git tree differs from its measured manifest")
		}
		return oid, binary.Len() != 0, nil
	}
	oid, _, err := tree(".")
	return oid, err
}

// Traverse only actual directory descriptors. Links are never followed, and
// every administrative spelling at any depth is refused before Git status.
func rejectNestedWorkspaceGit(ctx context.Context, root *os.File) error {
	_, original, err := dataIdentity(root)
	if err != nil {
		return err
	}
	count := 0
	var walk func(*os.File, int) error
	walk = func(parent *os.File, depth int) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if depth > 64 {
			return failure(api.CodeBudget, "workspace nested repository inventory exceeds its depth")
		}
		view, err := archFile(parent, ".", true)
		if err != nil {
			return err
		}
		defer view.Close()
		items, err := view.ReadDir(dataEntryLimit + 1)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		for _, item := range items {
			count++
			if count > dataEntryLimit {
				return failure(api.CodeBudget, "workspace repository inventory exceeds its entry bound")
			}
			if strings.EqualFold(item.Name(), ".git") {
				if depth == 0 && item.Name() == ".git" {
					continue
				}
				return failure(api.CodeIntegrity, "workspace contains a nested Git administrative entry")
			}
			var st unix.Stat_t
			if unix.Fstatat(int(parent.Fd()), item.Name(), &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Dev != original.Dev {
				return failure(api.CodeIntegrity, "workspace repository inventory changed its device or name")
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				child, err := archFile(parent, item.Name(), true)
				if err != nil {
					return err
				}
				err = errors.Join(walk(child, depth+1), child.Close())
				if err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(root, 0)
}

func checkWorkspaceTree(raw []byte) error {
	if len(raw) > api.MaxFrameBytes || len(raw) > 0 && raw[len(raw)-1] != 0 {
		return failure(api.CodeIntegrity, "native workspace tree observation is incomplete")
	}
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, name, ok := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !ok || len(fields) != 3 || !dataRelative(string(name)) {
			return failure(api.CodeIntegrity, "native workspace tree has an administrative or malformed entry")
		}
		if string(fields[0]) == "160000" || string(fields[1]) == "commit" {
			return failure(api.CodeIntegrity, "native workspace tree contains a gitlink")
		}
		if string(fields[1]) != "blob" || !cleanupHead(string(fields[2])) {
			return failure(api.CodeIntegrity, "native workspace tree has an unsupported object kind")
		}
	}
	return nil
}
