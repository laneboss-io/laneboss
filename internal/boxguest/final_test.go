package boxguest

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func findObject(t *testing.T, calls []curlCall, object string) curlCall {
	t.Helper()
	var matches []curlCall
	for _, call := range calls {
		if strings.HasSuffix(call.url, "name="+strings.ReplaceAll(object, "/", "%2F")) {
			matches = append(matches, call)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("object %q has %d uploads, want one", object, len(matches))
	}
	return matches[0]
}

func checkShutdown(t *testing.T, h *guardHarness, call curlCall, preempted string) {
	t.Helper()
	var marker map[string]string
	if err := json.Unmarshal([]byte(call.body), &marker); err != nil {
		t.Fatalf("shutdown JSON: %v", err)
	}
	if len(marker) != 3 || marker["preempted"] != preempted ||
		marker["at"] != "2033-05-18T03:33:20Z" || marker["run_id"] != "seed" {
		t.Fatalf("shutdown marker %#v, want preempted %q, UTC time and run id", marker, preempted)
	}
	wantURL := "https://storage.googleapis.com/" +
		"upload/storage/v1/b/sprout-bucket/" +
		"o?uploadType=media&name=runs%2Fseed%2Fshutdown.json"
	if call.url != wantURL {
		t.Fatalf("shutdown URL %q, want %q", call.url, wantURL)
	}
	checkRequest(t, call, filepath.Join(h.run, "shutdown.json"))
}

func TestFinalPreemption(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		fail  bool
		want  string
	}{
		{"true", "TRUE", false, "TRUE"},
		{"false", "FALSE", false, "FALSE"},
		{"invalid", "perhaps", false, "unknown"},
		{"failure", "", true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarvest(t)
			file := h.out("alpha.txt", "alpha\n", testNow-10)
			h.env["FAKE_PREEMPT_VALUE"] = tc.value
			if tc.fail {
				h.env["FAKE_PREEMPT_FAIL"] = "1"
			}
			h.execute(testNow, "final", 0)
			uploads := h.uploadsSince(0)
			if len(uploads) != 2 {
				t.Fatalf("final uploaded %d objects", len(uploads))
			}
			checkUpload(t, findObject(t, uploads, "runs/seed/out/alpha.txt"),
				"sprout-bucket", "runs/seed/out/alpha.txt", file, "alpha\n")
			checkShutdown(t, h, findObject(t, uploads, "runs/seed/shutdown.json"), tc.want)
			preemptURL := "http://metadata.google.internal/" +
				"computeMetadata/v1/instance/" + "preempted"
			calls := h.curlCalls()
			if len(calls) != 4 || calls[2].url != preemptURL ||
				!hasPair(calls[2].args, "--max-time", "3") ||
				!hasPair(calls[2].args, "-H", "Metadata-Flavor: Google") {
				t.Fatalf("preemption request or final order incorrect: %#v", calls)
			}
		})
	}
}

func TestFinalSkipped(t *testing.T) {
	h := newHarvest(t)
	good := h.out("good.txt", "good\n", testNow-10)
	h.out("bad name.txt", "bad\n", testNow-10)
	h.execute(testNow, "final", 0)
	uploads := h.uploadsSince(0)
	if len(uploads) != 3 {
		t.Fatalf("final uploaded %d objects", len(uploads))
	}
	checkUpload(t, findObject(t, uploads, "runs/seed/out/good.txt"),
		"sprout-bucket", "runs/seed/out/good.txt", good, "good\n")
	checkShutdown(t, h, findObject(t, uploads, "runs/seed/shutdown.json"), "TRUE")
	checkUpload(t, findObject(t, uploads, "runs/seed/sync-skipped.txt"),
		"sprout-bucket", "runs/seed/sync-skipped.txt",
		filepath.Join(h.run, "skipped"), "bad name.txt\n")
}

func TestFinalSyncFailure(t *testing.T) {
	h := newHarvest(t)
	file := h.out("alpha.txt", "alpha\n", testNow-10)
	h.env["FAKE_FAIL_OBJECT"] = "runs%2Fseed%2Fout%2Falpha.txt"
	h.execute(testNow, "final", 1)
	uploads := h.uploadsSince(0)
	if len(uploads) != 2 {
		t.Fatalf("failed sync suppressed final marker: %d uploads", len(uploads))
	}
	checkUpload(t, findObject(t, uploads, "runs/seed/out/alpha.txt"),
		"sprout-bucket", "runs/seed/out/alpha.txt", file, "alpha\n")
	checkShutdown(t, h, findObject(t, uploads, "runs/seed/shutdown.json"), "TRUE")
	absent(t, filepath.Join(h.run, "synced"))
}

func TestFinalUploadFailure(t *testing.T) {
	for _, object := range []string{"shutdown.json", "sync-skipped.txt"} {
		t.Run(object, func(t *testing.T) {
			h := newHarvest(t)
			if object == "sync-skipped.txt" {
				h.write(filepath.Join(h.run, "skipped"), "bad name.txt\n", 0644)
			}
			h.env["FAKE_FAIL_OBJECT"] = "runs%2Fseed%2F" + object
			h.execute(testNow, "final", 1)
			findObject(t, h.uploadsSince(0), "runs/seed/"+object)
			if !strings.Contains(readFile(t, h.log), "final harvest failed") {
				t.Fatal("final upload failure was not logged")
			}
		})
	}
}
