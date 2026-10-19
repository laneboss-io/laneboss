package admin

import (
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestVendorPublication(t *testing.T) {
	for _, retained := range []bool{false, true} {
		b := initialFixture(t)
		var runtime api.RuntimeManifest
		if err := api.DecodeObject(b.objects[b.manifest.Runtime.ID], &runtime); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"claudock", "claude"} {
			ref := api.BlobRef{ID: api.ID(name), Class: "artifact", Bytes: 65 << 20, SHA256: testDigest(name)}
			if retained {
				data := []byte("small vendor must also stay outside the store")
				ref.Bytes, ref.SHA256 = int64(len(data)), digestBytes(data)
				b.objects[ref.ID] = data
				b.manifest.Objects = append(b.manifest.Objects, ref)
			}
			runtime.Objects = append(runtime.Objects, api.RuntimeObject{ID: api.ID(name), Role: name, RootID: "runtime", RelativePath: name, Mode: 0555, Content: ref})
		}
		replaceInitialDoc(t, &b, &b.manifest.Runtime, runtime)
		var launch api.LaunchEnrollment
		if err := api.DecodeObject(b.objects[b.manifest.Launch.ID], &launch); err != nil {
			t.Fatal(err)
		}
		for i := range launch.Runtimes {
			launch.Runtimes[i].Manifest = b.manifest.Runtime
		}
		replaceInitialDoc(t, &b, &b.manifest.Launch, launch)
		actual, err := validateInitial(b.ref, b.raw, b.objects, b.manifest.Config)
		if retained {
			if err == nil {
				t.Error("vendor bytes entered the publication inventory")
			}
			continue
		}
		if err != nil {
			t.Error("file-only vendor pins were required as store objects", err)
			continue
		}
		tx, err := initialPlan(actual, api.Actor{Kind: "human", ID: "reviewer"}, "2026-10-18T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		for _, write := range tx.Writes.Objects {
			if write.ObjectKey == "claudock" || write.ObjectKey == "claude" {
				t.Fatal("vendor binary entered a store write")
			}
		}
	}
}
