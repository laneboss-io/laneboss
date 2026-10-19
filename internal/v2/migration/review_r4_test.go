package migration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func reviewStartBundle(lane string) *VerifiedBundle {
	return &VerifiedBundle{
		Quiescence:  QuiescenceReceipt{UnfinishedLanes: []string{lane}},
		Projections: map[string]map[string]any{},
		Events: []LegacyEventRecord{{Kind: "lane.started", Lane: lane, Payload: map[string]any{
			"runner": "claudock", "model": "fixture-model", "effort": "high",
			"session_id": "12345678-1234-4234-8234-123456789abc",
			"branch":     "safe/branch", "base": strings.Repeat("a", 40),
		}}},
	}
}

func TestReviewLaneArgument(t *testing.T) {
	t.Run("plan", func(t *testing.T) {
		for _, lane := range []string{"pending", "-pending", "--pending"} {
			if !ValidID(api.ID(lane)) {
				t.Fatal("lane fixture must pass the opaque ID check")
			}
			bundle := reviewStartBundle(lane)
			err := collectUnfinishedSessions(nil, bundle)
			if lane == "pending" {
				if err != nil || len(bundle.Unfinished) != 1 || bundle.Unfinished[0].Branch != "safe/branch" {
					t.Fatalf("valid lane with explicit branch was refused: %v", err)
				}
				continue
			}
			reviewError(t, err, api.CodeInvalid, "legacy.lane", "option-shaped legacy lane was accepted")
		}
	})
	for _, route := range []string{"option", "adopt"} {
		t.Run(route, func(t *testing.T) {
			service, _, scope, options := reviewRelaunch(t)
			target := &service.plans[options.PlanID].bundle.Unfinished[0]
			target.Branch = "safe/branch"
			prepared, err := service.PrepareRelaunch(context.Background(), scope, options)
			if err != nil {
				t.Fatalf("valid relaunch with explicit branch was refused: %v", err)
			}
			if prepared.AdoptRequest.Lane != options.Lane || prepared.Manifest.Workspace.Branch != target.Branch {
				t.Fatal("valid relaunch did not preserve lane and explicit branch")
			}
			options.Lane = "--pending"
			if route == "adopt" {
				target.Lane = options.Lane
			}
			_, err = service.PrepareRelaunch(context.Background(), scope, options)
			reviewError(t, err, api.CodeInvalid, "legacy.lane", "option-shaped relaunch lane was accepted")
		})
	}
}

func TestPlanLaneErr(t *testing.T) {
	for _, kind := range []string{"missing", "type"} {
		fields := []string{"runner", "session_id", "base", "model"}
		if kind == "type" {
			fields = []string{"runner", "model", "effort", "session_id", "branch", "base"}
		}
		for _, field := range fields {
			t.Run(kind+"-"+field, func(t *testing.T) {
				bundle := reviewStartBundle("pending-b")
				other := reviewStartBundle("pending-a")
				bundle.Quiescence.UnfinishedLanes = append(bundle.Quiescence.UnfinishedLanes, "pending-a")
				bundle.Events = append(bundle.Events, other.Events...)
				if err := collectUnfinishedSessions(nil, bundle); err != nil {
					t.Fatalf("valid multi-lane source was refused: %v", err)
				}
				payload := bundle.Events[0].Payload
				if kind == "missing" {
					delete(payload, field)
				} else {
					payload[field] = true
				}
				bundle.Unfinished = nil
				err := collectUnfinishedSessions(nil, bundle)
				reviewError(t, err, api.CodeInvalid, "legacy."+field, "legacy field validation was lost")
				reviewError(t, err, api.CodeInvalid, fmt.Sprintf("lane %q", "pending-b"), "legacy validation error omitted lane identity")
			})
		}
	}
}

func TestReviewRollbackReadLimit(t *testing.T) {
	for _, name := range []string{"small", "boundary", "oversized"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "input")
			original := []byte("rollback bytes")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			size := int64(len(original))
			if name != "small" {
				size = api.MaxObjectBytes
				if name == "oversized" {
					size++
				}
				if err := os.Truncate(path, size); err != nil {
					t.Fatal(err)
				}
			}
			parent, err := openRollbackDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			data, err := readRollbackFile(parent, "input")
			if name == "oversized" {
				if err == nil || !strings.Contains(err.Error(), "rollback input exceeds") || data != nil {
					t.Fatalf("oversized rollback input was accepted: bytes=%d error=%v", len(data), err)
				}
				return
			}
			if err != nil || int64(len(data)) != size || string(data[:min(len(data), len(original))]) != string(original) {
				t.Fatalf("bounded rollback input changed: bytes=%d error=%v", len(data), err)
			}
		})
	}
}
