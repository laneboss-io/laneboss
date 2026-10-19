package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() {
	for _, method := range []api.Method{
		"health", "operation.get", "blob.begin", "blob.chunk",
		"blob.commit", "blob.read", "store.verify", "store.rebuild",
	} {
		if err := RegisterInputValidator(method, "lb-v2-service", func(raw json.RawMessage) error {
			return wire.ValidateServiceInput(method, raw)
		}); err != nil {
			panic(err)
		}
	}
}

// runHealth maps file/flag inputs to api.HealthRequest, then calls health.
func runHealth(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runOperationGet maps file/flag inputs to api.OperationGetRequest, then calls operation.get.
func runOperationGet(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runBlobBegin maps file/flag inputs to api.BlobBeginRequest, then calls blob.begin.
func runBlobBegin(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runBlobChunk maps file/flag inputs to api.BlobChunk, then calls blob.chunk.
func runBlobChunk(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runBlobCommit maps file/flag inputs to api.BlobCommitRequest, then calls blob.commit.
func runBlobCommit(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runBlobRead maps file/flag inputs to api.BlobReadRequest, then calls blob.read.
func runBlobRead(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runStoreVerify maps file/flag inputs to api.VerifyRequest, then calls store.verify.
func runStoreVerify(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// runStoreRebuild maps file/flag inputs to api.RebuildRequest, then calls store.rebuild.
func runStoreRebuild(ctx context.Context, call Invocation) error {
	return lbV2ServiceRunRPC(ctx, call)
}

// Service commands accept one bounded schema-2 params file. Retry identities
// can be supplied explicitly; no local state path or direct-DB fallback exists.
func lbV2ServiceRunRPC(ctx context.Context, call Invocation) (resultErr error) {
	options := make(map[string]string)
	for i := 0; i < len(call.Args); i++ {
		name := call.Args[i]
		if name == "--binding" {
			name = "--binding-file"
		}
		switch name {
		case "--file", "--binding-file", "--request-id", "--idempotency-key", "--proof-file", "--format":
		default:
			return wire.Invalid("unknown service command flag")
		}
		if _, exists := options[name]; exists || i+1 >= len(call.Args) {
			return wire.Invalid("duplicate service flag or missing value")
		}
		i++
		if call.Args[i] == "" {
			return wire.Invalid("empty service flag value")
		}
		options[name] = call.Args[i]
	}
	if format := options["--format"]; format != "" && format != "json" {
		return wire.Invalid("service commands use JSON output")
	}
	spec, ok := api.Methods[call.Method]
	if !ok || spec.Owner != "lb-v2-service" {
		return wire.Invalid("incorrect service command method")
	}
	var params []byte
	var err error
	if path := options["--file"]; path != "" {
		params, err = lbV2ServiceReadFile(path)
	} else if call.Method == "health" {
		params, err = lbV2ServiceHealthParams()
	} else {
		return wire.Invalid("pass --file with the complete typed request params")
	}
	if err != nil {
		return err
	}
	if err := wire.ValidateServiceInput(call.Method, params); err != nil {
		return err
	}
	if id := options["--request-id"]; id != "" {
		if call.RequestID != "" {
			return wire.Invalid("duplicate request identity")
		}
		call.RequestID = api.ID(id)
	}
	if key := options["--idempotency-key"]; key != "" {
		if call.IdempotencyKey != "" {
			return wire.Invalid("duplicate idempotency identity")
		}
		call.IdempotencyKey = api.ID(key)
	}
	if path := options["--proof-file"]; path != "" {
		if call.ProofFile != "" {
			return wire.Invalid("duplicate proof file")
		}
		call.ProofFile = path
	}
	if path := options["--binding-file"]; path != "" {
		if call.Client != nil && call.Client.Options.BindingFile != path {
			return &api.Error{Code: api.CodeConflict, Message: "binding file conflicts with active client",
				Instead: "Keep this client bound and use a separately bound process."}
		}
		if call.integrateSocket == nil {
			call.integrateSocket = &integrateSocket{options: client.Options{Config: call.Config, BindingFile: path}}
		} else {
			if call.integrateSocket.connection != nil || call.integrateSocket.options.BindingFile != "" && call.integrateSocket.options.BindingFile != path {
				return wire.Invalid("binding conflicts with command socket")
			}
			call.integrateSocket.options.BindingFile = path
		}
	}
	return call.InvokeRaw(ctx, params)
}

func lbV2ServiceReadFile(path string) ([]byte, error) {
	return ReadInput(path, api.MaxFrameBytes)
}

func lbV2ServiceHealthParams() ([]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, wire.Invalid("installed artifact is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, wire.Invalid("installed artifact is unreadable")
	}
	hash := sha256.New()
	_, readErr := io.Copy(hash, file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, wire.Invalid("installed artifact hashing failed")
	}
	return json.Marshal(api.HealthRequest{ClientVersion: identity.Version,
		ArtifactSHA256: api.Digest(hex.EncodeToString(hash.Sum(nil)))})
}
