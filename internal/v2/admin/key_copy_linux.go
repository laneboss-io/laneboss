//go:build linux

package admin

import (
	"context"
	"errors"
	"io"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func keyStoreTarget(a api.CredentialProjectionAuthority, target api.CredentialTarget) bool {
	runner := a.Request.Handoff.Spec.Runner
	return runner != nil && runner.Driver == api.DriverClaudock && runner.Slot.Mode == "claude-api-key" &&
		target.SlotID == runner.Slot.ID && target.Delivery == "file" && target.RelativePath == claudock.KeyStorePath &&
		target.EnvironmentName == "ANTHROPIC_API_KEY" && target.FileMode == 0600
}

func copyKeyStore(ctx context.Context, input, output *os.File, size int64) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if input == nil || output == nil || size <= 0 || size > claudock.MaxAPIKeyBytes {
		return failure(api.CodeInvalid, "API key store copy exceeds its private bound")
	}
	key := make([]byte, int(size))
	defer clear(key)
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return failure(api.CodeIntegrity, "API key source offset is unavailable")
	}
	if _, err := io.ReadFull(input, key); err != nil {
		return failure(api.CodeIntegrity, "API key source is incomplete")
	}
	var extra [1]byte
	defer clear(extra[:])
	if n, err := input.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return failure(api.CodeIntegrity, "API key source length changed")
	}
	data, err := claudock.EncodeKeyStore(key)
	if err != nil {
		return err
	}
	defer clear(data)
	if n, err := output.Write(data); err != nil || n != len(data) {
		return failure(api.CodeIntegrity, "API key store private copy failed")
	}
	return output.Sync()
}
