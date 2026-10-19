package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
)

func integrateFlags(call Invocation) *flag.FlagSet {
	flags := flag.NewFlagSet(call.Path, flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Diagnostics never echo an arbitrary flag value.
	return flags
}

func integrateParse(flags *flag.FlagSet, args []string) error {
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return integrateInputError("unknown option, missing value or unexpected positional argument")
	}
	return nil
}

func integrateQueryInputs(call Invocation) (api.RecordQuery, error) {
	query := api.RecordQuery{Collection: integrateAliasCollection(call.Path), SearchMode: "keyword", Limit: 20}
	flags := integrateFlags(call)
	flags.StringVar(&query.Collection, "collection", query.Collection, "record collection")
	flags.StringVar(&query.Query, "query", "", "search text")
	flags.StringVar(&query.SearchMode, "mode", query.SearchMode, "keyword, vector or hybrid")
	flags.StringVar(&query.Cursor, "cursor", "", "opaque page cursor")
	flags.IntVar(&query.Limit, "limit", query.Limit, "records per page")
	life := flags.String("life", "", "authenticated life ID")
	if err := integrateParse(flags, call.Args); err != nil {
		return query, err
	}
	query.LifeID = api.ID(*life)
	if query.Collection == "" {
		return query, integrateInputError("a collection is required")
	}
	if fixed := integrateAliasCollection(call.Path); fixed != "" && fixed != query.Collection {
		return query, integrateInputError("alias collection conflicts with the requested collection")
	}
	return query, nil
}

func integrateAliasCollection(path string) string {
	switch {
	case path == "judge egress" || path == "decisions egress":
		return "judge_egress"
	case strings.HasPrefix(path, "decisions ") || path == "org capture-decision":
		return "decisions"
	}
	switch path {
	case "event append", "store record":
		return "observations"
	case "ledger":
		return "ledger"
	case "refusal", "lane refusals", "lane scan", "org refusals":
		return "refusals"
	case "tool":
		return "tools"
	case "org hook-history":
		return "observations"
	}
	return ""
}

func integrateValidateAlias(call Invocation, params any) error {
	if call.Path == "decisions stats" {
		return api.NotImplemented("lb-v2-integrate", "decision aggregate statistics")
	}
	if request, ok := params.(*api.ConfigReadRequest); ok {
		view := map[string]string{"config list": "list", "config path": "path", "config show": "show", "settings": "settings", "org roles list": "roles", "org channel read": "channels", "plugin": "plugins"}[call.Path]
		if view != "" && request.View != view {
			return integrateInputError("request view conflicts with the command alias")
		}
	}
	if query, ok := params.(*api.RecordQuery); ok {
		if fixed := integrateAliasCollection(call.Path); fixed != "" && query.Collection != fixed {
			return integrateInputError("request collection conflicts with the command alias")
		}
	}
	if request, ok := params.(*api.RecordAppendRequest); ok {
		if fixed := integrateAliasCollection(call.Path); fixed != "" && request.Collection != fixed {
			return integrateInputError("request collection conflicts with the command alias")
		}
	}
	if request, ok := params.(*api.DecisionMutateRequest); ok {
		if action := integrateAliasAction(call.Path); action != "" && request.Action != action {
			return integrateInputError("request action conflicts with the command alias")
		}
	}
	return nil
}

func integrateAliasAction(path string) string {
	if path == "org capture-decision" {
		return "add"
	}
	if strings.HasPrefix(path, "decisions ") && path != "decisions mutate" {
		return strings.TrimPrefix(path, "decisions ")
	}
	return ""
}

func integrateRunRecordsQuery(ctx context.Context, call Invocation) error {
	if call.Path == "decisions stats" {
		return api.NotImplemented("lb-v2-integrate", "decision aggregate statistics")
	}
	request, err := integrateQueryInputs(call)
	if err != nil {
		return err
	}
	return call.Invoke(ctx, request)
}

func integrateRunRecordsGet(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	id := flags.String("id", "", "record ID")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if *id == "" {
		return integrateInputError("record ID is required")
	}
	return call.Invoke(ctx, api.RecordGetRequest{RecordID: api.ID(*id)})
}

func integrateRunRecordsAppend(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	collection := flags.String("collection", integrateAliasCollection(call.Path), "record collection")
	path := flags.String("file", "", "bounded UTF-8 record file")
	contentRef := flags.String("content-ref", "", "committed BlobRef JSON file")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if (*path == "") == (*contentRef == "") || *collection == "" {
		return integrateInputError("one record file or content reference and a collection are required")
	}
	if fixed := integrateAliasCollection(call.Path); fixed != "" && fixed != *collection {
		return integrateInputError("alias collection conflicts with the requested collection")
	}
	ref, err := integrateRecordContent(ctx, &call, *path, *contentRef)
	if err != nil {
		return err
	}
	return call.Invoke(ctx, api.RecordAppendRequest{Collection: *collection, Content: ref, RelatedIDs: []api.ID{}})
}

func integrateRunDecisionsMutate(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	action := flags.String("action", integrateAliasAction(call.Path), "decision action")
	id := flags.String("id", "", "existing record ID")
	generation := flags.Uint64("expected-generation", 0, "exact base generation")
	path := flags.String("file", "", "exact decision content file")
	contentRef := flags.String("content-ref", "", "committed BlobRef JSON file for the exact proof")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if (*path == "") == (*contentRef == "") || *action == "" {
		return integrateInputError("decision action and one file or content reference are required")
	}
	if fixed := integrateAliasAction(call.Path); fixed != "" && fixed != *action {
		return integrateInputError("alias action conflicts with the requested action")
	}
	ref, err := integrateRecordContent(ctx, &call, *path, *contentRef)
	if err != nil {
		return err
	}
	return call.Invoke(ctx, api.DecisionMutateRequest{Action: *action, RecordID: api.ID(*id),
		ExpectedGeneration: api.Generation(*generation), Content: ref})
}

func integrateRunRecordsImport(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	collection := flags.String("collection", integrateAliasCollection(call.Path), "record collection")
	path := flags.String("manifest-ref", "", "committed manifest BlobRef JSON file")
	generation := flags.Uint64("expected-generation", 0, "exact base generation")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if *path == "" || *collection == "" {
		return integrateInputError("collection and committed manifest reference file are required")
	}
	raw, err := ReadInput(*path, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var ref api.BlobRef
	if err := api.DecodeObject(raw, &ref); err != nil {
		return err
	}
	return call.Invoke(ctx, api.TransferRequest{Collection: *collection, Manifest: ref,
		ExpectedGeneration: api.Generation(*generation)})
}

func integrateRunRecordsExport(ctx context.Context, call Invocation) error {
	request, err := integrateQueryInputs(call)
	if err != nil {
		return err
	}
	return call.Invoke(ctx, request)
}

func integrateRecordContent(ctx context.Context, call *Invocation, path, reference string) (api.BlobRef, error) {
	if reference != "" {
		raw, err := ReadInput(reference, api.MaxFrameBytes)
		if err != nil {
			return api.BlobRef{}, err
		}
		var ref api.BlobRef
		if err := api.DecodeObject(raw, &ref); err != nil {
			return api.BlobRef{}, err
		}
		return ref, nil
	}
	if call.ProofFile != "" {
		return api.BlobRef{}, &api.Error{Code: api.CodeInvalid, Message: "operation proof needs a committed content reference", Instead: "Upload the content first, confirm the exact mutation, then use --content-ref FILE --proof FILE with a retained --idempotency-key ID."}
	}
	return integrateUploadRecord(ctx, call, path)
}

func integrateUploadKey(key api.ID, method api.Method) (api.ID, error) {
	if key == "" {
		return "", &api.Error{Code: api.CodeInvalid, Message: "upload requires a retained mutation key", Instead: "Supply --idempotency-key ID and reuse it for the same file and mutation."}
	}
	hash := sha256.Sum256([]byte(string(key) + "\x00" + string(method)))
	return api.ID(hex.EncodeToString(hash[:16])), nil
}

func integrateUploadRecord(ctx context.Context, call *Invocation, path string) (api.BlobRef, error) {
	if _, err := integrateUploadKey(call.IdempotencyKey, "blob.begin"); err != nil {
		return api.BlobRef{}, err
	}
	data, err := ReadInput(path, api.MaxJudgeBytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	digest := sha256.Sum256(data)
	hash := api.Digest(hex.EncodeToString(digest[:]))
	rpc := func(method api.Method, params, result any) error {
		subcall := *call
		subcall.Method, subcall.Path, subcall.ProofFile = method, string(method), ""
		subcall.IdempotencyKey, err = integrateUploadKey(call.IdempotencyKey, method)
		if err != nil {
			return err
		}
		subcall.RequestID = ""
		var output bytes.Buffer
		subcall.Stdout = &output
		if err := subcall.Invoke(ctx, params); err != nil {
			return err
		}
		return api.DecodeObject(output.Bytes(), result)
	}
	var upload api.BlobUpload
	if err := rpc("blob.begin", api.BlobBeginRequest{Class: "record", Bytes: int64(len(data)), SHA256: hash}, &upload); err != nil {
		return api.BlobRef{}, err
	}
	if err := rpc("blob.chunk", api.BlobChunk{ObjectID: upload.ObjectID, Data: data, SHA256: hash}, &upload); err != nil {
		return api.BlobRef{}, err
	}
	var ref api.BlobRef
	if err := rpc("blob.commit", api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: hash}, &ref); err != nil {
		return api.BlobRef{}, err
	}
	if ref.SHA256 != hash || ref.Bytes != int64(len(data)) || ref.Class != "record" {
		return api.BlobRef{}, &api.Error{Code: api.CodeIntegrity, Message: "record upload receipt mismatch", Instead: "Preserve the original input and service receipt."}
	}
	return ref, nil
}

// Provision/run/harvest/end accept the full file-backed typed request, parsed by
// the common dispatcher. There is no shell, provider CLI or host-path fallback.
func integrateBoxRequestRequired(call Invocation) error {
	if len(call.Args) != 0 {
		return integrateInputError("unknown box option; use --request FILE for the exact typed body")
	}
	return integrateInputError("box operation requires --request FILE")
}

func integrateRunBoxLaunch(_ context.Context, call Invocation) error {
	return integrateBoxRequestRequired(call)
}
func integrateRunBoxRun(_ context.Context, call Invocation) error {
	return integrateBoxRequestRequired(call)
}
func integrateRunBoxHarvest(_ context.Context, call Invocation) error {
	return integrateBoxRequestRequired(call)
}
func integrateRunBoxEnd(_ context.Context, call Invocation) error {
	return integrateBoxRequestRequired(call)
}

func integrateRunBoxList(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	limit := flags.Int("limit", 20, "boxes per page")
	cursor := flags.String("cursor", "", "opaque cursor")
	life := flags.String("life", "", "life ID")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	return call.Invoke(ctx, api.ListRequest{LifeID: api.ID(*life), Cursor: *cursor, Limit: *limit})
}
