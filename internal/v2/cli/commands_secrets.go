package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

type lbV2SecretsFlags struct {
	request, proof, binding, requestID, idempotencyKey string
}

func lbV2SecretsInputCheck[I any](validate func(I) error) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var input I
		if err := wire.Decode(raw, &input, api.MaxFrameBytes); err != nil {
			return err
		}
		return validate(input)
	}
}

func init() {
	checks := []struct {
		method   api.Method
		validate func(json.RawMessage) error
	}{
		{"secret.key", lbV2SecretsInputCheck(secrets.ValidateKeyInput)},
		{"secret.stage", lbV2SecretsInputCheck(secrets.ValidateStageInput)},
		{"secret.import", lbV2SecretsInputCheck(secrets.ValidateImportInput)},
		{"secret.rotate", lbV2SecretsInputCheck(secrets.ValidateRotateInput)},
		{"secret.revoke", lbV2SecretsInputCheck(secrets.ValidateRevokeInput)},
		{"secret.list", lbV2SecretsInputCheck(secrets.ValidateListInput)},
	}
	for _, check := range checks {
		if err := RegisterInputValidator(check.method, "lb-v2-secrets", check.validate); err != nil {
			panic(err)
		}
	}
}

func lbV2SecretsParseFlags(args []string) (lbV2SecretsFlags, error) {
	var result lbV2SecretsFlags
	set := flag.NewFlagSet("secret", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&result.request, "request", "", "exact request JSON file")
	set.StringVar(&result.request, "input", "", "secret-specific request file alias")
	set.StringVar(&result.proof, "proof-file", "", "protected operation proof JSON file")
	set.StringVar(&result.binding, "binding-file", "", "installed service binding file")
	set.StringVar(&result.requestID, "request-id", "", "client request ID")
	set.StringVar(&result.idempotencyKey, "idempotency-key", "", "durable mutation retry ID")
	// The standard flag parser otherwise permits duplicate flags and echoes
	// invalid input, which may include an accidentally supplied credential.
	seen := make(map[string]bool)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			return result, wire.Error(api.CodeInvalid, "secret commands accept named file flags only")
		}
		name := strings.SplitN(strings.TrimPrefix(arg, "--"), "=", 2)[0]
		canonical := name
		if name == "input" {
			canonical = "request"
		}
		if set.Lookup(name) == nil || seen[canonical] {
			return result, wire.Error(api.CodeInvalid, "unknown or duplicate secret command flag")
		}
		seen[canonical] = true
		if !strings.Contains(arg, "=") {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "-") {
				return result, wire.Error(api.CodeInvalid, "missing secret command flag value")
			}
		}
	}
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return result, wire.Error(api.CodeInvalid, "invalid secret command flags")
	}
	values := map[string]string{"request": result.request, "proof-file": result.proof,
		"binding-file": result.binding, "request-id": result.requestID, "idempotency-key": result.idempotencyKey}
	for name, value := range values {
		if seen[name] && value == "" {
			return result, wire.Error(api.CodeInvalid, "secret file flags and IDs must not be empty")
		}
	}
	return result, nil
}

func lbV2SecretsReadInput(path string, protected bool, max int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, wire.Error(api.CodeInvalid, "cannot open secret request or proof file")
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, wire.Error(api.CodeInvalid, "secret request and proof inputs must be regular files")
	}
	if protected {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm()&0077 != 0 {
			file.Close()
			return nil, wire.Error(api.CodeForbidden, "operation proof file must be private and caller-owned")
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(file, max+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > max {
		return nil, wire.Error(api.CodeInvalid, "secret input file is unreadable or oversized")
	}
	return data, nil
}

func lbV2SecretsRPC[I, O any](ctx context.Context, call Invocation, method api.Method,
	empty bool, validate func(I) error, check func(O, I) error) (resultErr error) {
	if !wire.ID(call.Config) || call.Method != method {
		return wire.Error(api.CodeInvalid, "secret command requires its exact configuration and client method")
	}
	flags, err := lbV2SecretsParseFlags(call.Args)
	if err != nil {
		return err
	}
	// draft.4's common parser owns these options on normal CLI dispatch.
	// Direct feature invocations and the legacy proof-file alias still refuse
	// duplicates instead of changing an already selected request/proof binding.
	if call.ProofFile != "" {
		if flags.proof != "" {
			return wire.Error(api.CodeInvalid, "duplicate secret proof option")
		}
		flags.proof = call.ProofFile
	}
	if call.RequestID != "" {
		if flags.requestID != "" {
			return wire.Error(api.CodeInvalid, "duplicate secret request ID")
		}
		flags.requestID = string(call.RequestID)
	}
	if call.IdempotencyKey != "" {
		if flags.idempotencyKey != "" {
			return wire.Error(api.CodeInvalid, "duplicate secret retry ID")
		}
		flags.idempotencyKey = string(call.IdempotencyKey)
	}
	data := []byte("{}")
	if flags.request != "" {
		data, err = lbV2SecretsReadInput(flags.request, false, api.MaxFrameBytes)
		if err != nil {
			return err
		}
	} else if !empty {
		return wire.Error(api.CodeInvalid, "secret command requires --request FILE")
	}
	var input I
	if err := wire.Decode(data, &input, api.MaxFrameBytes); err != nil {
		return err
	}
	if err := validate(input); err != nil {
		return err
	}
	if flags.proof != "" {
		proofData, err := lbV2SecretsReadInput(flags.proof, true, 4096)
		if err != nil {
			return err
		}
		var proof api.ProofRef
		if err := wire.Decode(proofData, &proof, 4096); err != nil {
			return err
		}
		if !wire.ID(string(proof.ID)) || !lbV2SecretsFuture(proof.ExpiresAt) {
			return wire.Error(api.CodeForbidden, "operation proof differs from the secret intent or has expired")
		}
		proofMethod, proofParams := method, json.RawMessage(data)
		if method == "secret.key" || method == "secret.stage" || method == "secret.list" {
			proofMethod, proofParams = "human.session", json.RawMessage(`{}`)
		}
		expected, err := api.RequestDigest(api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
			Config: call.Config, Method: proofMethod, Params: proofParams})
		if err != nil || !wire.Digest(proof.RequestSHA256) || proof.RequestSHA256 != expected {
			return wire.Error(api.CodeForbidden, "operation proof differs from the secret intent or has expired")
		}
	}
	if call.Client != nil && call.Client.Options.Config != call.Config {
		return wire.Error(api.CodeInvalid, "secret client configuration differs from the command")
	}
	if flags.binding != "" {
		if call.Client != nil && call.Client.Options.BindingFile != flags.binding ||
			call.integrateSocket != nil && call.integrateSocket.options.BindingFile != flags.binding {
			return wire.Error(api.CodeConflict, "secret command cannot replace an existing client binding")
		}
		if call.Client == nil && call.integrateSocket == nil {
			// Direct feature invocation only. Normal CLI dispatch owns its socket.
			socket := &integrateSocket{options: client.Options{Config: call.Config, BindingFile: flags.binding}}
			call.integrateSocket = socket
			defer func() {
				if socket.connection != nil {
					if closeErr := socket.connection.Close(); closeErr != nil {
						resultErr = errors.Join(resultErr, closeErr)
					}
				}
			}()
		}
	}
	call.ProofFile, call.RequestID, call.IdempotencyKey = flags.proof, api.ID(flags.requestID), api.ID(flags.idempotencyKey)
	// InvokeRaw owns request preparation, retained mutation keys, human.session
	// and the shared/borrowed connection lifetime. Retain feature result checks
	// before publishing any receipt to the caller.
	var encoded bytes.Buffer
	checkedCall := call
	checkedCall.Stdout = &encoded
	if err := checkedCall.InvokeRaw(ctx, append(json.RawMessage(nil), data...)); err != nil {
		return err
	}
	var output O
	if err := wire.Decode(encoded.Bytes(), &output, api.MaxFrameBytes); err != nil {
		return wire.Error(api.CodeIntegrity, "secret response has an invalid result shape")
	}
	if err := check(output, input); err != nil {
		return err
	}
	if err := json.NewEncoder(call.Stdout).Encode(output); err != nil {
		return wire.Error(api.CodeIntegrity, "cannot write secret command receipt")
	}
	return nil
}

func lbV2SecretsFuture(value api.Timestamp) bool {
	t, err := time.Parse(time.RFC3339Nano, string(value))
	return err == nil && strings.HasSuffix(string(value), "Z") && time.Now().Before(t)
}

func lbV2SecretsInfoValid(info api.SecretInfo) bool {
	return wire.Name(info.Name) && wire.Name(info.Version) &&
		wire.ID(string(info.SourceHandle)) && wire.ID(string(info.KeyID))
}

func runSecretKey(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.key", true, secrets.ValidateKeyInput,
		func(result api.SecretKey, _ api.Empty) error {
			if !wire.ID(string(result.ID)) || result.Algorithm != secrets.StageAlgorithm ||
				len(result.PublicKey) != 32 || !lbV2SecretsFuture(result.ExpiresAt) {
				return wire.Error(api.CodeIntegrity, "invalid advertised secret upload key")
			}
			return nil
		})
}

func runSecretStage(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.stage", false, secrets.ValidateStageInput,
		func(result api.SecretStage, input api.SecretStageRequest) error {
			if !wire.ID(string(result.ID)) || result.Name != input.Name || result.Version != input.Version ||
				!lbV2SecretsFuture(result.ExpiresAt) {
				return wire.Error(api.CodeIntegrity, "secret stage receipt differs from the request")
			}
			return nil
		})
}

func runSecretImport(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.import", false, secrets.ValidateImportInput,
		func(result api.SecretInfo, input api.SecretImportRequest) error {
			if !lbV2SecretsInfoValid(result) || result.Name != input.Name || result.Version != input.Version || result.Revoked {
				return wire.Error(api.CodeIntegrity, "secret import receipt differs from the request")
			}
			return nil
		})
}

func runSecretRotate(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.rotate", false, secrets.ValidateRotateInput,
		func(result api.SecretInfo, input api.SecretRotateRequest) error {
			if !lbV2SecretsInfoValid(result) || result.Name != input.Name || result.Version == input.ExpectedVersion || result.Revoked {
				return wire.Error(api.CodeIntegrity, "secret rotation did not produce a new source version")
			}
			return nil
		})
}

func runSecretRevoke(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.revoke", false, secrets.ValidateRevokeInput,
		func(result api.Operation, _ api.SecretRevokeRequest) error {
			if !wire.ID(string(result.ID)) {
				return wire.Error(api.CodeIntegrity, "secret revocation has no operation receipt")
			}
			switch result.Status {
			case "pending", "running", "succeeded", "failed", "cancelled":
				return nil
			default:
				return wire.Error(api.CodeIntegrity, "secret revocation has an invalid operation status")
			}
		})
}

func runSecretList(ctx context.Context, call Invocation) error {
	return lbV2SecretsRPC(ctx, call, "secret.list", true, secrets.ValidateListInput,
		func(result api.SecretList, _ api.Empty) error {
			if result.Secrets == nil {
				return wire.Error(api.CodeIntegrity, "secret list must contain an array")
			}
			for _, info := range result.Secrets {
				if !lbV2SecretsInfoValid(info) {
					return wire.Error(api.CodeIntegrity, "secret list contains invalid metadata")
				}
			}
			return nil
		})
}
