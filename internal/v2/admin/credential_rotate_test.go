package admin

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/secrets"
)

func TestParseCredentialRotateArgs(t *testing.T) {
	request, err := ParseCredentialRotateArgs([]string{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeClaudeAPIKey,
		"--profile", "profile-a", "--login", "login-a", "--source-handle", "source-a", "--source-version", "source-b"})
	if err != nil {
		t.Fatal(err)
	}
	if request.Command != secrets.CredentialRotateCommand || request.ProfileID != "profile-a" || request.LoginID != "login-a" || request.SourceVersion != "source-b" {
		t.Fatalf("unexpected request: %+v", request)
	}
}

func TestRotateArgsRejectUnsafeForms(t *testing.T) {
	tests := [][]string{
		{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeCodexFile, "--profile-id", "profile-a", "--login-id", "login-a", "--token", "value"},
		{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeCodexFile, "--profile-id", "profile-a", "--profile-id", "profile-b", "--login-id", "login-a"},
		{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeCodexFile, "--profile-id", "profile-a", "--login-id", "/tmp/login"},
	}
	for _, args := range tests {
		if _, err := ParseCredentialRotateArgs(args); err == nil {
			t.Fatalf("unsafe ROTATE form was accepted: %v", args)
		}
	}
}

type rotateOwner struct {
	result secrets.CredentialRotationResult
	got    secrets.CredentialRotationRequest
}

func (o *rotateOwner) RotateCredential(_ context.Context, request secrets.CredentialRotationRequest, _ secrets.CredentialRotationHandlers) (secrets.CredentialRotationResult, error) {
	o.got = request
	return o.result, nil
}
