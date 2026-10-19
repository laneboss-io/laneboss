package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/secrets"
)

type credentialRotateCaller struct {
	result secrets.CredentialRotationResult
}

func (c credentialRotateCaller) RotateCredential(context.Context, secrets.CredentialRotationRequest, secrets.CredentialRotationHandlers) (secrets.CredentialRotationResult, error) {
	return c.result, nil
}

func TestRunCredentialRotateCommand(t *testing.T) {
	args := []string{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeCodexFile,
		"--profile-id", "profile-a", "--login-id", "login-a"}
	caller := credentialRotateCaller{result: secrets.CredentialRotationResult{Command: secrets.CredentialRotateCommand,
		Mode: secrets.CredentialModeCodexFile, ProfileID: "profile-a", LoginID: "login-a", Generation: 2, QuarantineReleased: true}}
	var output bytes.Buffer
	if err := RunCredentialRotateCommand(context.Background(), args, caller, secrets.CredentialRotationHandlers{}, &output); err != nil {
		t.Fatal(err)
	}
	var result secrets.CredentialRotationResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result != caller.result {
		t.Fatalf("receipt=%+v, want %+v", result, caller.result)
	}
}

func TestRotateRejectsMismatchedOwner(t *testing.T) {
	args := []string{secrets.CredentialRotateCommand, "--mode", secrets.CredentialModeCodexFile,
		"--profile-id", "profile-a", "--login-id", "login-a"}
	caller := credentialRotateCaller{result: secrets.CredentialRotationResult{Command: secrets.CredentialRotateCommand,
		Mode: secrets.CredentialModeCodexFile, ProfileID: "other", LoginID: "login-a", QuarantineReleased: true}}
	if err := RunCredentialRotateCommand(context.Background(), args, caller, secrets.CredentialRotationHandlers{}, &bytes.Buffer{}); err == nil {
		t.Fatal("mismatched owner result was accepted")
	}
}
