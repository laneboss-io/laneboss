package grants_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Reseal worker-only manifest and job bytes for the confined core's validators.
// This does not establish service-stage acceptance or native authentication.
func materializationRootModes(t *testing.T, f *materializationFixture, sourceMode, outputMode uint32) {
	t.Helper()
	var input dataworker.MaterializationInput
	if err := api.DecodeObject(f.blobs[f.stage.Worker.Input.ID], &input); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		ref  *api.BlobRef
		mode uint32
	}{{&input.Source.Object, sourceMode}, {&input.Output, outputMode}} {
		var object api.ObjectManifest
		if err := api.DecodeObject(f.blobs[item.ref.ID], &object); err != nil {
			t.Fatal(err)
		}
		object.Entries = append(object.Entries, api.ObjectEntry{Path: ".", Kind: "directory", Mode: item.mode})
		if err := manifest.Object(object); err != nil {
			t.Fatal("root mode fixture is not a valid object manifest", err)
		}
		*item.ref = f.encoded(item.ref.ID, item.ref.Class, object, f.stage.Reservation.OperationID)
	}
	input.Source.Base = string(input.Source.Object.SHA256)
	input.Grants.Data[0].SourceSHA256 = input.Source.Object.SHA256
	input.Grants.SHA256 = ""
	digest, err := manifest.HashValue(input.Grants)
	if err != nil {
		t.Fatal(err)
	}
	input.Grants.SHA256 = digest
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.stage.Worker.Input = f.object(f.stage.Worker.Input.ID, "materialize_input", canonical, f.stage.Reservation.OperationID)
	f.stage.Plan.Input = f.stage.Worker.Input
	f.stage.Claim.Record.Effect.Worker.Input = f.stage.Worker.Input
	f.principal.Lease.Input = f.stage.Worker.Input
	f.principal.Claim.Record.Effect.Worker.Input = f.stage.Worker.Input
	f.principal.Record.GrantsSHA256 = input.Grants.SHA256
}

func TestMaterializationRootMode(t *testing.T) {
	for _, item := range []struct {
		name                   string
		sourceMode, outputMode uint32
		invalid                bool
	}{
		{"private", 0700, 0700, false},
		{"public", 0755, 0755, true},
		{"restricted", 0500, 0500, true},
		{"output-public", 0700, 0755, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			f := newMaterializationFixture(t)
			materializationRootModes(t, f, item.sourceMode, item.outputMode)
			receipt, err := dataworker.RunMaterialization(context.Background(), f.job())
			if item.invalid {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeInvalid || typed.Owner != "lb-v2-grants" || typed.Message != "materialization root mode must be 0700" {
					t.Fatal("incompatible manifest root was not refused before copy", err)
				}
				if !reflect.DeepEqual(receipt, api.WorkerResultReceipt{}) || f.resultCalls != 0 {
					t.Fatal("incompatible manifest root produced an acknowledgement")
				}
				for _, path := range []string{f.workspacePath, f.homePath} {
					entries, err := os.ReadDir(path)
					if err != nil || len(entries) != 0 {
						t.Fatal("incompatible manifest root wrote destination entries", err)
					}
				}
			} else {
				if err != nil || receipt != f.result.ResultReceipt || f.resultCalls != 1 {
					t.Fatal("private explicit manifest root did not materialize", err)
				}
				actual, err := os.ReadFile(filepath.Join(f.workspacePath, "main.txt"))
				if err != nil || !reflect.DeepEqual(actual, f.blobs["file-bytes"]) {
					t.Fatal("private explicit root changed copied file bytes", err)
				}
			}
			for _, path := range []string{f.workspacePath, f.homePath} {
				info, err := os.Lstat(path)
				if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
					t.Fatal("materialization changed private destination root mode", err)
				}
			}
		})
	}
}
