package service

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets"
)

func TestUsageJobsPort(t *testing.T) {
	server := &Server{}
	jobs, ok := any(server).(secrets.UsageJobControl)
	if !ok {
		t.Fatal("installed server has no confined UsageJobs adapter")
	}
	if scope, err := jobs.StartUsage(context.Background(), api.Scope{}, api.UsageWindowRequest{}); err == nil || scope.Connection != nil || scope.Frame != nil {
		t.Fatal("unbound usage adapter manufactured an authenticated worker scope")
	}
	if result, err := jobs.RunUsage(context.Background(), "unissued-stage"); err == nil || result.Scope.Connection != nil || len(result.Raw) != 0 {
		t.Fatal("unbound usage adapter manufactured native command output")
	}
}

func TestUsagePublicCallerRefuses(t *testing.T) {
	jobs, ok := any(&Server{}).(secrets.UsageJobControl)
	if !ok {
		t.Fatal("installed usage admission port is absent")
	}
	_, err := jobs.StartUsage(context.Background(), api.Scope{Config: "usage-case", Actor: api.Actor{Kind: "lane", ID: "lane-one", Level: 6}}, api.UsageWindowRequest{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite && typed.Code != api.CodeForbidden {
		t.Fatal("public caller received no typed stopped usage admission", err)
	}
}
