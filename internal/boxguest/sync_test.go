package boxguest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/boxcore"
)

func newHarvest(t *testing.T) *guardHarness {
	t.Helper()
	return newGuard(t, boxcore.GuestSpec{
		Provider: "gcp", Bucket: "sprout-bucket", ObjectPrefix: "runs/seed",
		RunID: "seed", IdleMin: 2,
	})
}

func TestSyncFirstPass(t *testing.T) {
	h := newHarvest(t)
	first := h.out("alpha.txt", "alpha\n", testNow-10)
	second := h.out("nested/beta.log", "beta\n", testNow-10)
	h.execute(testNow, "sync", 0)
	calls := h.curlCalls()
	tokenURL := "http://metadata.google.internal/" +
		"computeMetadata/v1/instance/" + "service-accounts/default/token"
	if len(calls) != 3 || calls[0].url != tokenURL ||
		!hasPair(calls[0].args, "-H", "Metadata-Flavor: Google") ||
		!hasPair(calls[0].args, "--max-time", "5") {
		t.Fatalf("token request or upload count incorrect: %#v", calls)
	}
	uploads := h.uploadsSince(0)
	if len(uploads) != 2 {
		t.Fatalf("got %d uploads", len(uploads))
	}
	checkUpload(t, findObject(t, uploads, "runs/seed/out/alpha.txt"),
		"sprout-bucket", "runs/seed/out/alpha.txt", first, "alpha\n")
	checkUpload(t, findObject(t, uploads, "runs/seed/out/nested/beta.log"),
		"sprout-bucket", "runs/seed/out/nested/beta.log", second, "beta\n")
	if got := markerTime(t, filepath.Join(h.run, "synced")); !got.Equal(time.Unix(testNow, 0)) {
		t.Fatalf("sync marker %v, want start time", got)
	}
	absent(t, filepath.Join(h.run, "synced.new"))
}

func TestSyncSkipsNames(t *testing.T) {
	h := newHarvest(t)
	good := h.out("good.txt", "good\n", testNow-10)
	h.out("bad name.txt", "space\n", testNow-10)
	h.out("bad\nline.txt", "newline\n", testNow-10)
	h.execute(testNow, "sync", 0)
	uploads := h.uploadsSince(0)
	if len(uploads) != 1 {
		t.Fatalf("unsafe names caused %d uploads", len(uploads))
	}
	checkUpload(t, uploads[0], "sprout-bucket", "runs/seed/out/good.txt",
		good, "good\n")
	skipped := readFile(t, filepath.Join(h.run, "skipped"))
	for _, name := range []string{"bad name.txt\n", "bad\nline.txt\n"} {
		if !strings.Contains(skipped, name) {
			t.Fatalf("skipped log %q lacks %q", skipped, name)
		}
	}
}

func TestSyncRetry(t *testing.T) {
	for _, prior := range []bool{false, true} {
		name := "first"
		if prior {
			name = "later"
		}
		t.Run(name, func(t *testing.T) {
			h := newHarvest(t)
			marker := filepath.Join(h.run, "synced")
			if prior {
				h.out("old.txt", "old\n", testNow-10)
				h.execute(testNow, "sync", 0)
			}
			first := h.out("one.txt", "one\n", testNow+1)
			second := h.out("nested/two.txt", "two\n", testNow+1)
			h.env["FAKE_FAIL_OBJECT"] = "runs%2Fseed%2Fout%2Fnested%2Ftwo.txt"
			start := len(h.curlCalls())
			h.execute(testNow+60, "sync", 1)
			if len(h.uploadsSince(start)) != 2 {
				t.Fatal("failed pass did not attempt both changed files")
			}
			if prior {
				if got := markerTime(t, marker); !got.Equal(time.Unix(testNow, 0)) {
					t.Fatalf("failed upload advanced marker to %v", got)
				}
			} else {
				absent(t, marker)
			}
			if !strings.Contains(readFile(t, h.log), "harvest sync failed") {
				t.Fatal("upload failure was not logged")
			}
			delete(h.env, "FAKE_FAIL_OBJECT")
			start = len(h.curlCalls())
			h.execute(testNow+120, "sync", 0)
			uploads := h.uploadsSince(start)
			if len(uploads) != 2 {
				t.Fatalf("retry uploaded %d files", len(uploads))
			}
			checkUpload(t, findObject(t, uploads, "runs/seed/out/one.txt"),
				"sprout-bucket", "runs/seed/out/one.txt", first, "one\n")
			checkUpload(t, findObject(t, uploads, "runs/seed/out/nested/two.txt"),
				"sprout-bucket", "runs/seed/out/nested/two.txt", second, "two\n")
			if got := markerTime(t, marker); !got.Equal(time.Unix(testNow+120, 0)) {
				t.Fatalf("successful retry marker %v", got)
			}
		})
	}
}

func TestSyncNoToken(t *testing.T) {
	for _, mode := range []string{"fail", "empty", "missing"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarvest(t)
			h.out("alpha.txt", "alpha\n", testNow-10)
			h.env["FAKE_TOKEN_MODE"] = mode
			h.execute(testNow, "sync", 1)
			if len(h.uploadsSince(0)) != 0 {
				t.Fatal("uploaded without an access token")
			}
			absent(t, filepath.Join(h.run, "synced"))
			absent(t, filepath.Join(h.run, "synced.new"))
		})
	}
}

func TestSyncDuringUpload(t *testing.T) {
	h := newHarvest(t)
	file := h.out("alpha.txt", "alpha\n", testNow-10)
	h.env["FAKE_CHANGE_FILE"] = file
	h.execute(testNow, "sync", 0)
	if got := markerTime(t, filepath.Join(h.run, "synced")); !got.Equal(time.Unix(testNow, 0)) {
		t.Fatalf("marker created after upload at %v", got)
	}
	delete(h.env, "FAKE_CHANGE_FILE")
	if err := os.Remove(filepath.Join(h.root, "touch-clock")); err != nil {
		t.Fatal(err)
	}
	start := len(h.curlCalls())
	h.execute(testNow+60, "sync", 0)
	uploads := h.uploadsSince(start)
	if len(uploads) != 1 {
		t.Fatalf("file changed during upload was lost: %d uploads", len(uploads))
	}
	checkUpload(t, uploads[0], "sprout-bucket", "runs/seed/out/alpha.txt",
		file, "alpha\n")
}

func TestSyncFindFailure(t *testing.T) {
	h := newHarvest(t)
	marker := filepath.Join(h.run, "synced")
	h.write(marker, "prior marker\n", 0644)
	h.setTime(marker, testNow-100)
	h.fake("find", "exit 1\n")
	h.execute(testNow, "sync", 1)
	if got := markerTime(t, marker); !got.Equal(time.Unix(testNow-100, 0)) {
		t.Fatalf("find failure advanced marker to %v", got)
	}
	if readFile(t, marker) != "prior marker\n" || len(h.uploadsSince(0)) != 0 {
		t.Fatal("find failure changed the marker or uploaded files")
	}
}

func TestSyncFailureStillGuards(t *testing.T) {
	for _, mode := range []string{"done", "idle"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarvest(t)
			h.env["FAKE_TOKEN_MODE"] = "fail"
			if mode == "done" {
				h.write(h.spec.DoneFiles[0], "done\n", 0644)
				h.write(h.load, "8.00 8.00 8.00 1/1 1\n", 0644)
			} else {
				h.write(filepath.Join(h.run, "idle-since"), "1\n", 0644)
			}
			h.execute(testNow, "", 0)
			h.shutdowns(1)
			if !strings.Contains(readFile(t, h.log), "harvest sync failed") {
				t.Fatal("best effort failure was not logged")
			}
		})
	}
}

func TestEmptyBucket(t *testing.T) {
	for _, mode := range []string{"", "sync", "final"} {
		t.Run("mode-"+mode, func(t *testing.T) {
			h := newGuard(t, boxcore.GuestSpec{Provider: "gcp"})
			h.execute(testNow, mode, 0)
			if len(h.curlCalls()) != 0 {
				t.Fatal("empty bucket contacted metadata or storage")
			}
			if mode == "" {
				idleSince(h, testNow)
			} else {
				absent(t, filepath.Join(h.run, "idle-since"))
			}
			h.shutdowns(0)
		})
	}
}
