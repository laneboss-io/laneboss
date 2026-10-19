package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func bad(t *testing.T, err error) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeInvalid {
		t.Fatalf("expected invalid input, got %v", err)
	}
}

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{
		`{}`, `{"grant_set_id":null}`, `{"grant_set_id":7}`,
		`{"grant_set_id":"x","extra":false}`,
		`{"grant_set_id":"x","grant_set_id":"y"}`,
		`{"grant_set_id":"x","grant_\u0073et_id":"y"}`,
		`{"grant_set_id":"x"} {}`,
		`{"grant_set_id":"\ud800"}`, `{"grant_set_id":"\udc00"}`,
		`{"Grant_set_id":"x"}`,
		string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}),
	} {
		var target api.GrantGetRequest
		bad(t, Decode([]byte(input), &target))
	}
	var target api.GrantGetRequest
	if err := Decode([]byte(" {\"grant_set_id\": \"x\"} \n"), &target); err != nil || target.GrantSetID != "x" {
		t.Fatalf("valid typed input: %v", err)
	}
	for _, value := range []string{"9007199254740992", "-1", "1.0", "1e0"} {
		_, err := Canonical([]byte(`{"n":` + value + `}`))
		bad(t, err)
	}
	var request api.GrantRequest
	bad(t, Decode([]byte(`{"resources":[],"data":null,"secrets":[],"profiles":[],"network":[],"channels":[]}`), &request))
}

func TestCanonicalJSON(t *testing.T) {
	input := []byte(" {\"z\": 3, \"a\": [true,\"<>&\\u2028\"], \"😀\":0, \"\ue000\":1 }")
	actual, err := Canonical(input)
	if err != nil {
		t.Fatal(err)
	}
	expected := "{\"a\":[true,\"<>&\u2028\"],\"z\":3,\"😀\":0,\"\ue000\":1}"
	if string(actual) != expected {
		t.Fatal("canonical ordering or string escaping differs")
	}
	second, err := Canonical(actual)
	if err != nil || !bytes.Equal(actual, second) {
		t.Fatal("canonicalization is not idempotent")
	}
	if Hash(input) == Hash(actual) {
		t.Fatal("raw and canonical byte hashes were conflated")
	}
	var target api.GrantGetRequest
	if err := Decode([]byte(`{"grant_set_id":"\ud83d\ude00"}`), &target); err != nil {
		t.Fatal("paired Unicode surrogate was rejected", err)
	}
}

func TestPathsAndTargets(t *testing.T) {
	for _, value := range []string{".", "src", "src/a.go", "a..b"} {
		if err := Relative(value); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{"", "/a", "../a", "a/../b", "a//b", "a/./b", "a/", "a\\b", ".git", "x/.GIT/config", "a\x00b"} {
		bad(t, Relative(value))
	}
	if Beneath("api", "api-private") {
		t.Fatal("string prefix widened a subtree")
	}
	for _, value := range []string{"/work/main", "/data/contract"} {
		if err := Destination(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"/work", "/work/main/sub", "/data/..", "/run/control", "/work/./main"} {
		bad(t, Destination(value))
	}
	for _, target := range []string{"HOME", "PATH", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "LANEBOSS_CONFIG", "CODEX_HOME", "BASH_ENV", "XDG_CONFIG_HOME", "GCONV_PATH", "OPENAI_API_KEY", "SSH_AUTH_SOCK"} {
		bad(t, SecretTarget("env", target))
	}
	if err := SecretTarget("env", "TASK_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := SecretTarget("file", "keys/task"); err != nil {
		t.Fatal(err)
	}
	bad(t, SecretTarget("file", "../outside"))
	if err := Selections([]string{"m7i.large", "project/global/image-v1"}); err != nil {
		t.Fatal(err)
	}
}

func tree() api.ObjectManifest {
	ref := api.BlobRef{ID: "file", SHA256: Hash([]byte("input")), Bytes: 5, Class: "artifact"}
	return api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{
		{Path: "child/input", Kind: "file", Mode: 0644, Content: &ref},
		{Path: "private/canary", Kind: "file", Mode: 0644, Content: &ref},
		{Path: "child/safe", Kind: "symlink", Mode: 0777, LinkTarget: "input"},
	}}
}

func TestObjectSelection(t *testing.T) {
	object := tree()
	selected, err := Select(object, "child")
	if err != nil || len(selected) != 2 {
		t.Fatalf("narrow safe tree: %v", err)
	}
	for _, entry := range selected {
		if strings.HasPrefix(entry.Path, "private/") {
			t.Fatal("private subtree was included")
		}
	}
	bad(t, func() error { _, err := Select(object, "child/safe"); return err }())
	object.Entries[2].LinkTarget = "../private/canary"
	if err := Object(object); err != nil {
		t.Fatal("internal whole-tree link should be valid", err)
	}
	_, err = Select(object, "child")
	bad(t, err)
	object.Entries[2].LinkTarget = "../../outside"
	bad(t, Object(object))
	object.Entries[2].LinkTarget = "safe"
	bad(t, Object(object))
}

func TestObjectHostAliases(t *testing.T) {
	for _, kind := range []string{"hardlink", "mount", "fifo", "socket", "device"} {
		object := tree()
		object.Entries = append(object.Entries, api.ObjectEntry{Path: "alias", Kind: kind, Mode: 0644})
		bad(t, Object(object))
	}
	for _, mutate := range []func(*api.ObjectManifest){
		func(o *api.ObjectManifest) { o.Entries[0].Mode = 04755 },
		func(o *api.ObjectManifest) { o.Entries[0].Path = ".git/objects/info/alternates" },
		func(o *api.ObjectManifest) { o.Entries[0].Path = "../private" },
		func(o *api.ObjectManifest) { o.Entries[0].Path = "child/safe/nested" },
		func(o *api.ObjectManifest) { o.Entries[2].LinkTarget = "/host/private" },
		func(o *api.ObjectManifest) { o.Entries = append(o.Entries, o.Entries[0]) },
	} {
		object := tree()
		mutate(&object)
		bad(t, Object(object))
	}
}

func TestRootManifest(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	root := api.RootGrantManifest{Schema: "laneboss.root-grants.v2",
		Data: []api.DataGrant{{SourceObjectID: "tree", SourceSHA256: Hash([]byte("tree")),
			RelativePath: ".", Access: "ro", Delivery: "copy", Destination: "/data/source",
			HistoryScope: "snapshot", ExpiresAt: api.Timestamp(now.Add(time.Hour).Format(time.RFC3339Nano))}},
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Profiles: []api.ProfileGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{}}
	if err := Root(root, now); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	var decoded api.RootGrantManifest
	if err := Decode(data, &decoded); err != nil {
		t.Fatal(err)
	}
	root.Data[0].ID = "forged"
	bad(t, Root(root, now))
	root.Data[0].ID = ""
	root.Data[0].ParentGrantID = "forged-parent"
	bad(t, Root(root, now))
	root.Data[0].ParentGrantID = ""
	root.Data[0].SourceObjectID = "/host/path"
	bad(t, Root(root, now))
}
