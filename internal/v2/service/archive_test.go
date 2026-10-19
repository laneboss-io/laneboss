package service

import (
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestArchNeedsNative(t *testing.T) {
	err := supportsEffect(api.RuntimeServices{}, api.Effect{Worker: &api.WorkerPlan{Kind: "archive"}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-admin" {
		t.Fatal("archive dispatch lost the native helper refusal", err)
	}
}
func TestCleanNeedsCollector(t *testing.T) {
	err := supportsEffect(api.RuntimeServices{}, api.Effect{Clean: &api.CleanRequest{}})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-grants" {
		t.Fatal("cleanup dispatch lost the grants collector refusal", err)
	}
}
