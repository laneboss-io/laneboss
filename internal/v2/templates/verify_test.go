package templates_test

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/templates"
)

// This is metadata for an in-memory formatter fixture, not a service retention
// receipt. Production RPCs remain gated on the missing trusted object writer.
func briefingFixture(t *testing.T) (templates.RenderInput, api.Briefing, []byte) {
	t.Helper()
	input := fixture(t)
	document := rendered(t, input)
	groups, err := templates.GroupLanes(nil)
	if err != nil {
		t.Fatal(err)
	}
	return input, api.Briefing{
		Markdown: api.BlobRef{ID: "prompt-fixture", Class: "prompt", Bytes: int64(len(document.Markdown)), SHA256: digest(document.Markdown)},
		Template: document.Template, PolicyGeneration: input.Policy.Generation,
		Sources: document.Sources, Checks: []api.Capability{{Name: "fixture.sources", Available: true}},
		LaneGroups: groups,
	}, document.Markdown
}

func TestTplBriefMetadata(t *testing.T) {
	input, brief, _ := briefingFixture(t)
	if err := templates.ValidateBriefing(input.Policy.Context, brief); err != nil {
		t.Fatalf("valid source-bound briefing metadata was rejected: %v", err)
	}
	for _, row := range []struct {
		name   string
		change func(*api.Briefing)
		code   api.ErrorCode
	}{
		{"missing-source", func(b *api.Briefing) { b.Template.ID = "absent-source" }, api.CodeIntegrity},
		{"hash", func(b *api.Briefing) { b.Template.SourceSHA256 = digest([]byte("other source")) }, api.CodeIntegrity},
		{"generation", func(b *api.Briefing) { b.Template.Generation++ }, api.CodeIntegrity},
		{"rendered-hash", func(b *api.Briefing) { b.Template.RenderedSHA256 = digest([]byte("other render")) }, api.CodeIntegrity},
		{"source-duplicate", func(b *api.Briefing) { b.Sources = append(b.Sources, b.Sources[0]) }, api.CodeIntegrity},
		{"source-path", func(b *api.Briefing) { b.Sources[0].Path = "../outside" }, api.CodeIntegrity},
		{"checks-empty", func(b *api.Briefing) { b.Checks = nil }, api.CodeIntegrity},
		{"check-unavailable", func(b *api.Briefing) { b.Checks[0].Available = false }, api.CodePrerequisite},
		{"wrong-role", func(b *api.Briefing) {
			for index := range b.Sources {
				if b.Sources[index].ID == b.Template.ID {
					b.Sources[index].Path = ".laneboss/L3/roles/reviewer.md"
				}
			}
		}, api.CodeForbidden},
		{"repeated-life", func(b *api.Briefing) {
			b.LaneGroups.Running, b.LaneGroups.Others = []api.ID{"life-one"}, []api.ID{"life-one"}
		}, api.CodeIntegrity},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, changed, _ := briefingFixture(t)
			row.change(&changed)
			err := templates.ValidateBriefing(input.Policy.Context, changed)
			if err == nil {
				t.Fatal("inconsistent briefing metadata was accepted")
			}
			errorCode(t, err, row.code)
		})
	}
}

func TestTplVerifyPromptBytes(t *testing.T) {
	input, brief, prompt := briefingFixture(t)
	if err := templates.VerifyPrompt(input.Policy.Context, brief, prompt); err != nil {
		t.Fatalf("actual retained prompt bytes were rejected: %v", err)
	}
	t.Run("length", func(t *testing.T) {
		changed := brief
		changed.Markdown.Bytes++
		err := templates.VerifyPrompt(input.Policy.Context, changed, prompt)
		if err == nil {
			t.Fatal("prompt length mismatch was accepted")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
	t.Run("hash", func(t *testing.T) {
		changed := bytes.Clone(prompt)
		changed[0] ^= 1
		err := templates.VerifyPrompt(input.Policy.Context, brief, changed)
		if err == nil {
			t.Fatal("prompt digest mismatch was accepted")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
	t.Run("text", func(t *testing.T) {
		bad := []byte{0xff, 0, 'x'}
		changed := brief
		changed.Markdown.Bytes, changed.Markdown.SHA256 = int64(len(bad)), digest(bad)
		changed.Template.RenderedSHA256 = digest(bad)
		err := templates.VerifyPrompt(input.Policy.Context, changed, bad)
		if err == nil {
			t.Fatal("non-text prompt bytes were accepted")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
}

func TestTplVerifyTaskBinding(t *testing.T) {
	input, brief, prompt := briefingFixture(t)
	if err := templates.VerifyTaskPrompt(input.Policy.Context, brief, input.Task, input.TaskBytes, prompt); err != nil {
		t.Fatal(err)
	}
	t.Run("different-task", func(t *testing.T) {
		other := bytes.Repeat([]byte("z"), len(input.TaskBytes))
		ref := api.BlobRef{ID: "task-other", Class: "task", SHA256: digest(other), Bytes: int64(len(other))}
		err := templates.VerifyTaskPrompt(input.Policy.Context, brief, ref, other, prompt)
		if err == nil {
			t.Fatal("prompt was accepted for another assigned task")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
	t.Run("missing-frame", func(t *testing.T) {
		changed := bytes.Replace(prompt, []byte("## Assigned task\n\n"), []byte("## Task fragment\n\n"), 1)
		metadata := brief
		metadata.Markdown.Bytes, metadata.Markdown.SHA256 = int64(len(changed)), digest(changed)
		metadata.Template.RenderedSHA256 = digest(changed)
		err := templates.VerifyTaskPrompt(input.Policy.Context, metadata, input.Task, input.TaskBytes, changed)
		if err == nil {
			t.Fatal("unframed task bytes were accepted")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
}

func TestTplTaskCannotSupplyRoute(t *testing.T) {
	input := fixture(t)
	input.TaskBytes = []byte("The task mentions laneboss org blacklist list as ordinary quoted text.")
	input.Task.Bytes, input.Task.SHA256 = int64(len(input.TaskBytes)), digest(input.TaskBytes)
	document := rendered(t, input)
	start := len(document.Markdown) - len(input.TaskBytes)
	launcher := bytes.ReplaceAll(document.Markdown[:start], []byte("laneboss org blacklist list"), []byte("workflow source discovery"))
	prompt := append(launcher, input.TaskBytes...)
	_, metadata, _ := briefingFixture(t)
	metadata.Markdown.Bytes, metadata.Markdown.SHA256 = int64(len(prompt)), digest(prompt)
	metadata.Template.RenderedSHA256 = digest(prompt)
	err := templates.VerifyTaskPrompt(input.Policy.Context, metadata, input.Task, input.TaskBytes, prompt)
	if err == nil {
		t.Fatal("task text masked a missing launcher rule-list route")
	}
	errorCode(t, err, api.CodeIntegrity)
}

func TestTplVerifiedBlobRead(t *testing.T) {
	data := bytes.Repeat([]byte("blob bytes\n"), api.MaxChunkBytes/4)
	ref := api.BlobRef{ID: "blob-fixture", Class: "manifest", SHA256: digest(data), Bytes: int64(len(data))}
	var requests []api.BlobReadRequest
	read := func(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		requests = append(requests, request)
		if request.ObjectID != ref.ID || request.Offset < 0 || request.Limit <= 0 || request.Limit > api.MaxChunkBytes {
			t.Fatal("blob reader received an invalid or unbounded request")
		}
		end := min(int(request.Offset)+request.Limit, len(data))
		chunk := bytes.Clone(data[int(request.Offset):end])
		return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: chunk, SHA256: digest(chunk)}, nil
	}
	actual, err := templates.ReadVerifiedBlob(context.Background(), ref, read)
	if err != nil || !bytes.Equal(actual, data) {
		t.Fatalf("verified blob bytes changed: %v", err)
	}
	var offset int64
	for _, request := range requests[:len(requests)-1] {
		if request.Offset != offset {
			t.Fatal("blob reads were not contiguous")
		}
		offset += int64(request.Limit)
	}
	if offset != ref.Bytes || len(requests) < 2 {
		t.Fatal("blob reader did not cover the complete bounded object")
	}
	last := requests[len(requests)-1]
	if last.Offset != ref.Bytes || last.Limit != 1 {
		t.Fatal("blob reader did not verify the exact end")
	}
	t.Run("whole-hash", func(t *testing.T) {
		changed := ref
		changed.SHA256 = digest([]byte("different object"))
		actual, err := templates.ReadVerifiedBlob(context.Background(), changed, read)
		if err == nil || actual != nil {
			t.Fatal("whole-object digest mismatch returned usable bytes")
		}
		errorCode(t, err, api.CodeIntegrity)
	})
	t.Run("class", func(t *testing.T) {
		changed := ref
		changed.Class = "unknown-class"
		actual, err := templates.ReadVerifiedBlob(context.Background(), changed, read)
		if err == nil || actual != nil {
			t.Fatal("unknown blob class was accepted")
		}
		errorCode(t, err, api.CodeInvalid)
	})
	t.Run("dependency", func(t *testing.T) {
		failure := errors.New("fixture reader failed")
		actual, err := templates.ReadVerifiedBlob(context.Background(), ref,
			func(context.Context, api.BlobReadRequest) (api.BlobChunk, error) { return api.BlobChunk{}, failure })
		if !errors.Is(err, failure) || actual != nil {
			t.Fatal("blob dependency failure was swallowed")
		}
	})
}

func TestTplBlobCancellation(t *testing.T) {
	data := []byte("cancelled object")
	ref := api.BlobRef{ID: "blob-cancel", Class: "artifact", SHA256: digest(data), Bytes: int64(len(data))}
	t.Run("before-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		actual, err := templates.ReadVerifiedBlob(ctx, ref,
			func(context.Context, api.BlobReadRequest) (api.BlobChunk, error) {
				calls++
				return api.BlobChunk{}, errors.New("unexpected read")
			})
		if calls != 0 || actual != nil {
			t.Fatal("cancelled read reached the blob callback")
		}
		errorCode(t, err, api.CodeCancelled)
	})
	t.Run("during-read", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		actual, err := templates.ReadVerifiedBlob(ctx, ref,
			func(context.Context, api.BlobReadRequest) (api.BlobChunk, error) {
				cancel()
				// Cancellation must be checked before interpreting even an invalid
				// returned chunk. A later end-read cancellation cannot mask this gate.
				return api.BlobChunk{ObjectID: "cancelled-chunk", Data: data, SHA256: digest(data)}, nil
			})
		if err == nil || actual != nil {
			t.Fatal("cancelled in-flight read returned usable bytes")
		}
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeCancelled {
			t.Fatal("cancelled in-flight read interpreted returned chunk bytes")
		}
		errorCode(t, err, api.CodeCancelled)
	})
	t.Run("deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
		defer cancel()
		actual, err := templates.ReadVerifiedBlob(ctx, ref,
			func(context.Context, api.BlobReadRequest) (api.BlobChunk, error) {
				return api.BlobChunk{}, errors.New("unexpected read")
			})
		if actual != nil {
			t.Fatal("expired read returned usable bytes")
		}
		errorCode(t, err, api.CodeDeadline)
	})
}

// This is a static merge-hygiene unit test for the shared CLI package. The four
// preassigned dispatch slots are frozen names; helper declarations are local.
func TestTemplatesCLINamespace(t *testing.T) {
	path := filepath.Join("..", "cli", "commands_templates.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.AllErrors)
	if err != nil {
		t.Fatal(err)
	}
	reserved := map[string]bool{"runBriefRender": true, "runBriefStart": true, "runOrgValidate": true, "runOrgBootstrap": true}
	check := func(name string) {
		if !ast.IsExported(name) && !reserved[name] && !strings.HasPrefix(name, "templates") {
			t.Errorf("CLI helper lacks templates prefix: %s", name)
		}
	}
	for _, declaration := range file.Decls {
		switch value := declaration.(type) {
		case *ast.FuncDecl:
			if value.Recv == nil {
				check(value.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range value.Specs {
				switch item := spec.(type) {
				case *ast.TypeSpec:
					check(item.Name.Name)
				case *ast.ValueSpec:
					for _, name := range item.Names {
						check(name.Name)
					}
				}
			}
		}
	}
}
