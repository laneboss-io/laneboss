package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/migration"
	migv2 "laneboss.io/laneboss/migration/v2"
)

func init() {
	validators := []struct {
		method api.Method
		check  func(json.RawMessage) error
	}{
		{"migration.plan", func(raw json.RawMessage) error {
			var request api.MigrationPlanRequest
			if err := api.DecodeObject(raw, &request); err != nil {
				return err
			}
			return migrationValidateFileInput(Invocation{}, &request)
		}},
		{"migration.apply", func(raw json.RawMessage) error {
			var request api.MigrationApplyRequest
			if err := api.DecodeObject(raw, &request); err != nil {
				return err
			}
			return migrationValidateFileInput(Invocation{}, &request)
		}},
	}
	for _, validator := range validators {
		if err := RegisterInputValidator(validator.method, "lb-v2-migration", validator.check); err != nil {
			panic(err)
		}
	}
}

// Migration uses the common invocation for request sealing, retained mutation
// keys, binding selection, human.session and the lifetime of its one socket.
func runMigrationPlan(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	manifestFile := flags.String("manifest", "", "local frozen migration manifest")
	sourceManifestFile := flags.String("source-manifest", "", "alias for --manifest")
	contentRef := flags.String("content-ref", "", "committed manifest BlobRef JSON file")
	sourceVersion := flags.String("source-version", "", "frozen source version")
	dbFile := flags.String("db", "", "legacy decisions database (requires a frozen manifest)")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if *dbFile != "" {
		// A local database is not evidence that dispatch and all old writers have
		// stopped. Never manufacture quiescence/verification receipts from it.
		return migrationCLIInvalid("--db requires independently verified frozen inputs; use --content-ref FILE --source-version VERSION or an exact --request FILE")
	}
	if *manifestFile != "" && *sourceManifestFile != "" {
		return migrationCLIInvalid("--manifest and --source-manifest are aliases; pass only one")
	}
	if *sourceManifestFile != "" {
		*manifestFile = *sourceManifestFile
	}
	if (*manifestFile == "") == (*contentRef == "") {
		return migrationCLIInvalid("pass exactly one of --manifest FILE or --content-ref FILE")
	}

	var request api.MigrationPlanRequest
	if *contentRef != "" {
		raw, err := migrationReadLocalFile(*contentRef, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		if err := api.DecodeObject(raw, &request.SourceManifest); err != nil {
			return err
		}
		request.SourceVersion = *sourceVersion
	} else {
		if call.ProofFile != "" {
			return migrationCLIInvalid("a human read proof requires a committed manifest reference; upload first, then use --content-ref FILE --proof FILE")
		}
		// Upload mutations derive stable subkeys from the caller's retained key.
		// Check it before reading or uploading any bytes.
		if _, err := integrateUploadKey(call.IdempotencyKey, "migration-manifest/blob.begin"); err != nil {
			return err
		}
		raw, err := migrationReadLocalFile(*manifestFile, api.MaxObjectBytes)
		if err != nil {
			return err
		}
		var manifest api.MigrationManifest
		if err := api.DecodeObject(raw, &manifest); err != nil {
			return err
		}
		if manifest.Schema != migration.SchemaMigrationManifest {
			return migrationCLIInvalid("manifest schema must be laneboss.migration.v2")
		}
		if *sourceVersion != "" && manifest.SourceVersion != *sourceVersion {
			return migrationCLIInvalid("--source-version conflicts with manifest.source_version")
		}
		if !migv2.SupportedSourceVersion(manifest.SourceVersion) {
			return migrationCLIInvalid("unsupported source_version")
		}
		if err := migration.ValidateObjectManifest(manifest.Inventory); err != nil {
			return err
		}
		for _, ref := range []api.BlobRef{manifest.Quiescence, manifest.Verification} {
			if err := migration.ValidateBlobRef(ref, "manifest"); err != nil {
				return err
			}
		}
		ref, err := migrationUploadBlob(ctx, call, raw, "manifest")
		if err != nil {
			return err
		}
		request = api.MigrationPlanRequest{SourceVersion: manifest.SourceVersion, SourceManifest: ref}
	}
	if err := migrationValidateFileInput(call, &request); err != nil {
		return err
	}
	return call.Invoke(ctx, request)
}

func runMigrationApply(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	planID := flags.String("plan-id", "", "migration plan ID")
	planAlias := flags.String("plan", "", "alias for --plan-id")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if *planID != "" && *planAlias != "" {
		return migrationCLIInvalid("--plan-id and --plan are aliases; pass only one")
	}
	if *planAlias != "" {
		*planID = *planAlias
	}
	request := api.MigrationApplyRequest{PlanID: api.ID(*planID)}
	if err := migrationValidateFileInput(call, &request); err != nil {
		return err
	}
	return call.Invoke(ctx, request)
}

// The registered file forms and ergonomic handlers share semantic validation.
// Proof-file checks additionally apply when an ergonomic invocation has one.
func migrationValidateFileInput(call Invocation, params any) error {
	if call.ProofFile != "" {
		raw, err := migrationReadLocalFile(call.ProofFile, 65536)
		if err != nil {
			return err
		}
		var proof api.ProofRef
		if err := api.DecodeObject(raw, &proof); err != nil {
			return err
		}
		if !migration.ValidID(proof.ID) || !migration.ValidDigest(proof.RequestSHA256) || !migration.ValidTimestamp(proof.ExpiresAt) {
			return migrationCLIInvalid("invalid proof reference file")
		}
	}
	switch request := params.(type) {
	case *api.MigrationPlanRequest:
		if !migv2.SupportedSourceVersion(request.SourceVersion) {
			return migrationCLIInvalid("unsupported source_version")
		}
		return migration.ValidateBlobRef(request.SourceManifest, "manifest")
	case *api.MigrationApplyRequest:
		if !migration.ValidID(request.PlanID) {
			return migrationCLIInvalid("plan_id is required and must be a valid ID")
		}
		return nil
	default:
		return migrationCLIInvalid("unexpected migration request type")
	}
}

func migrationUploadBlob(ctx context.Context, call Invocation, data []byte, class string) (api.BlobRef, error) {
	var zero api.BlobRef
	if int64(len(data)) > api.MaxObjectBytes {
		return zero, migrationCLIInvalid("file exceeds maximum blob size of 64 MiB")
	}
	sha := migration.DigestBytes(data)
	rpc := func(method api.Method, suffix string, params, result any) error {
		subcall := call
		subcall.Method, subcall.Path, subcall.ProofFile = method, string(method), ""
		subcall.RequestID = ""
		key, err := integrateUploadKey(call.IdempotencyKey, api.Method("migration-manifest/"+string(method)+suffix))
		if err != nil {
			return err
		}
		subcall.IdempotencyKey = key
		var output bytes.Buffer
		subcall.Stdout = &output
		if err := subcall.Invoke(ctx, params); err != nil {
			return err
		}
		return api.DecodeObject(output.Bytes(), result)
	}
	var upload api.BlobUpload
	if err := rpc("blob.begin", "", api.BlobBeginRequest{Class: class, Bytes: int64(len(data)), SHA256: sha}, &upload); err != nil {
		return zero, err
	}
	if !migration.ValidID(upload.ObjectID) || upload.MaxChunkBytes <= 0 || upload.MaxChunkBytes > api.MaxChunkBytes {
		return zero, &api.Error{Code: api.CodeIntegrity, Message: "invalid migration upload lease", Instead: "Retain the response and repair the service upload contract.", Owner: "lb-v2-migration"}
	}
	for offset := 0; offset < len(data); {
		end := offset + upload.MaxChunkBytes
		if end > len(data) {
			end = len(data)
		}
		part := data[offset:end]
		chunk := api.BlobChunk{ObjectID: upload.ObjectID, Offset: int64(offset), Data: part, SHA256: migration.DigestBytes(part)}
		var response api.BlobUpload
		if err := rpc("blob.chunk", fmt.Sprintf("/%d", offset), chunk, &response); err != nil {
			return zero, err
		}
		if response.ObjectID != upload.ObjectID {
			return zero, &api.Error{Code: api.CodeIntegrity, Message: "migration chunk receipt belongs to another upload", Instead: "Retain the response and repair the service.", Owner: "lb-v2-migration"}
		}
		offset = end
	}
	var committed api.BlobRef
	if err := rpc("blob.commit", "", api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: sha}, &committed); err != nil {
		return zero, err
	}
	if committed.ID != upload.ObjectID || committed.SHA256 != sha || committed.Bytes != int64(len(data)) || committed.Class != class {
		return zero, &api.Error{Code: api.CodeIntegrity, Message: "committed migration blob does not match the upload", Instead: "Preserve the input and upload receipts.", Owner: "lb-v2-migration"}
	}
	return committed, nil
}

func migrationReadLocalFile(path string, maxBytes int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, migrationCLIInvalid("file path is empty")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, migrationCLIInvalid("cannot open input file as a regular non-symlink file")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, migrationCLIInvalid("input file must be a regular file")
	}
	if st.Size() == 0 || st.Size() > maxBytes {
		return nil, migrationCLIInvalid(fmt.Sprintf("input file size must be between 1 and %d bytes", maxBytes))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, migrationCLIInvalid("cannot read bounded input file")
	}
	return data, nil
}

func migrationCLIInvalid(msg string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: msg, Instead: "Pass valid migration CLI flags and committed file inputs.", Owner: "lb-v2-migration"}
}
