package boxgcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

// TestFetchHarvest rejects wrong rsync argv, constant counts, lost no-match and links.
func TestFetchHarvest(t *testing.T) {
	cases := []struct {
		name, prefix, source string
		noMatch, stdoutMatch bool
		link                 bool
		count                int
	}{
		{"recursive", "runs", "gs://demo-results/runs/run-1/out", false, false, false, 3},
		{"empty-prefix", "", "gs://demo-results/run-1/out", false, false, false, 1},
		{"trim-prefix", "/runs/", "gs://demo-results/runs/run-1/out", false, false, false, 2},
		{"no-match", "runs", "gs://demo-results/runs/run-1/out", true, false, false, 0},
		{"stdout-no-match", "runs", "gs://demo-results/runs/run-1/out", true, true, false, 0},
		{"symbolic-link", "runs", "gs://demo-results/runs/run-1/out", false, false, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.ObjectPrefix = tc.prefix
			dir := filepath.Join(t.TempDir(), "harvest")
			f := &boxexec.Fake{Handlers: []boxexec.Handler{ownedHandler(t), {Name: "gcloud", ArgsContain: []string{"storage rsync"},
				Respond: func(cmd boxexec.Cmd, n int) (boxexec.Result, error) {
					requireArgs(t, cmd.Args, []string{
						"storage", "rsync", "--recursive", tc.source, dir, "--project=demo-project", "--quiet",
					})
					info, err := os.Stat(dir)
					if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
						t.Fatal("harvest directory was not created with mode 0700")
					}
					if tc.noMatch {
						if tc.stdoutMatch {
							return boxexec.Result{Stdout: []byte("No URLs matched")}, nil
						}
						return boxexec.Result{Code: 1, Stderr: []byte("No URLs matched")}, nil
					}
					if err := os.Mkdir(filepath.Join(dir, "logs"), 0700); err != nil {
						t.Fatal(err)
					}
					paths := []string{"result.txt", "logs/first.txt", "logs/second.txt"}
					for _, path := range paths[:tc.count] {
						if err := os.WriteFile(filepath.Join(dir, path), []byte("harvest bytes"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if tc.link {
						target := filepath.Join(t.TempDir(), "outside.txt")
						if err := os.WriteFile(target, []byte("outside"), 0600); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(target, filepath.Join(dir, "linked.txt")); err != nil {
							t.Fatal(err)
						}
					}
					return boxexec.Result{}, nil
				},
			}}}
			got, err := New(cfg, f, testOptions()).FetchHarvest(context.Background(), testBox(), "run-1", dir)
			if tc.noMatch {
				requireKind(t, err, boxcore.KindNotFound)
				if got != 0 {
					t.Fatal("missing harvest has a nonzero count")
				}
			} else if tc.link {
				if err == nil || got != 0 {
					t.Fatal("harvest followed a link or returned a partial success")
				}
			} else if err != nil || got != tc.count {
				t.Fatal("file count did not reflect the actual nested files")
			}
			// The fence reads the machine first; the copy follows it.
			requireVerbs(t, f, "describe", "rsync")
		})
	}
	t.Run("linked-root", func(t *testing.T) {
		parent := t.TempDir()
		link := filepath.Join(parent, "linked")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		f := &boxexec.Fake{}
		count, err := New(testConfig(), f, testOptions()).FetchHarvest(context.Background(), testBox(), "run-1", link)
		if err == nil || count != 0 || len(f.Calls) != 0 {
			t.Fatal("linked harvest root reached rsync")
		}
	})
	t.Run("denied", func(t *testing.T) {
		// The machine is ours, so the refusal comes from the copy itself.
		f := &boxexec.Fake{Handlers: []boxexec.Handler{ownedHandler(t), {Name: "gcloud", ArgsContain: []string{"storage rsync"},
			Respond: func(boxexec.Cmd, int) (boxexec.Result, error) {
				return boxexec.Result{Code: 1, Stderr: []byte("PERMISSION_DENIED")}, nil
			}}}}
		count, err := New(testConfig(), f, testOptions()).FetchHarvest(context.Background(), testBox(), "run-1", t.TempDir())
		requireKind(t, err, boxcore.KindDenied)
		if count != 0 {
			t.Fatal("failed rsync returned a file count")
		}
		requireVerbs(t, f, "describe", "rsync")
	})
}
