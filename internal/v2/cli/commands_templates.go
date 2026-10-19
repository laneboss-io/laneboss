package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/templates"
)

var templatesValidators = templatesRegisterValidators()

func templatesInputCheck[Request any](validate func(Request) error) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var request Request
		if err := templates.DecodeJSON(raw, &request); err != nil {
			return err
		}
		return validate(request)
	}
}

func templatesRegisterValidators() error {
	entries := []struct {
		method api.Method
		check  func(json.RawMessage) error
	}{
		{"brief.render", templatesInputCheck(templatesValidateRenderRequest)},
		{"brief.start", templatesInputCheck(templatesValidateStartRequest)},
		{"org.validate", templatesInputCheck(templatesValidateOrgRequest)},
		{"org.bootstrap", templatesInputCheck(templatesValidateBootstrapRequest)},
	}
	var registrationError error
	for _, entry := range entries {
		check := entry.check
		validate := func(raw json.RawMessage) error {
			if registrationError != nil {
				return registrationError
			}
			return check(raw)
		}
		if err := RegisterInputValidator(entry.method, "lb-v2-templates", validate); err != nil {
			registrationError = err
			return err
		}
	}
	return nil
}

func templatesValidateRenderRequest(request api.TemplateRequest) error {
	if err := templatesValidateContext(request.Context); err != nil {
		return err
	}
	if !templatesID.MatchString(string(request.GrantSetID)) || !templatesBlob(request.Task, "task") {
		return templatesInvalid("render requires a committed task and grant-set identifier")
	}
	return nil
}

func templatesValidateStartRequest(request api.BriefingRequest) error {
	if err := templatesValidateContext(api.RoleContext{Level: request.Level, Role: request.Role}); err != nil {
		return err
	}
	if request.LifeID != "" && !templatesID.MatchString(string(request.LifeID)) {
		return templatesInvalid("invalid briefing life identifier")
	}
	return nil
}

func templatesValidateOrgRequest(request api.OrgValidateRequest) error {
	if request.Generation == 0 || request.Generation > 1<<53-1 {
		return templatesInvalid("--generation is required and must be an exact positive JSON integer")
	}
	return nil
}

func templatesValidateBootstrapRequest(request api.BootstrapRequest) error {
	if !templatesID.MatchString(request.OrgName) || !templatesBlob(request.SourceManifest, "manifest") {
		return templatesInvalid("bootstrap requires an org name and a committed source manifest")
	}
	return nil
}

// runBriefRender maps file/flag inputs to api.TemplateRequest, then calls brief.render.
func runBriefRender(ctx context.Context, call Invocation) (resultErr error) {
	options, err := templatesParseFlags(call, "render")
	if err != nil {
		return err
	}
	defer templatesClose(&options, &resultErr)
	var request api.TemplateRequest
	if options.request != "" {
		if err := templatesReadRequest(&options, &request); err != nil {
			return err
		}
	} else {
		request.Context = api.RoleContext{Level: options.level, Role: options.role, InstanceID: api.ID(options.instance)}
		request.GrantSetID = api.ID(options.grants)
		if err := templatesValidateContext(request.Context); err != nil {
			return err
		}
		if !templatesID.MatchString(options.grants) {
			return templatesInvalid("--grant-set-id is required")
		}
		data, err := templatesReadFile(options.brief, api.MaxObjectBytes)
		if err != nil {
			return err
		}
		if len(data) == 0 || !utf8.Valid(data) || bytes.ContainsRune(data, 0) {
			return templatesInvalid("--brief must contain nonempty UTF-8 task bytes")
		}
		var grants api.GrantSet
		if err := templatesCall(ctx, call, &options, "grants.get", api.GrantGetRequest{GrantSetID: request.GrantSetID}, &grants); err != nil {
			return err
		}
		if grants.ID != request.GrantSetID || !templatesID.MatchString(string(grants.LifeID)) || grants.Revoked {
			return templatesIntegrity("render grant-set lookup differs from the requested scope")
		}
		var lane api.Lane
		if err := templatesCall(ctx, call, &options, "lane.status", api.LifeRef{LifeID: grants.LifeID}, &lane); err != nil {
			return err
		}
		assigned := lane.Task
		if options.taskRef != "" {
			if err := templatesReadJSON(options.taskRef, &assigned); err != nil {
				return err
			}
		}
		if lane.LifeID != grants.LifeID || lane.GrantSetID != grants.ID || lane.Level != request.Context.Level ||
			lane.Role != request.Context.Role || !templatesBlob(assigned, "task") ||
			assigned.Bytes != int64(len(data)) || assigned.SHA256 != templatesHash(data) {
			return templatesIntegrity("--brief bytes differ from the committed assigned task reference")
		}
		request.Task = assigned
	}
	if err := templatesValidateRenderRequest(request); err != nil {
		return err
	}
	var result api.Briefing
	if err := templatesCall(ctx, call, &options, "brief.render", request, &result); err != nil {
		return err
	}
	return templatesPrintBrief(ctx, call, &options, request.Context, &request.Task, result)
}

// runBriefStart maps file/flag inputs to api.BriefingRequest, then calls brief.start.
func runBriefStart(ctx context.Context, call Invocation) (resultErr error) {
	options, err := templatesParseFlags(call, "start")
	if err != nil {
		return err
	}
	defer templatesClose(&options, &resultErr)
	request := api.BriefingRequest{Role: options.role, Level: options.level, LifeID: api.ID(options.life)}
	if options.request != "" {
		if err := templatesReadRequest(&options, &request); err != nil {
			return err
		}
	}
	if err := templatesValidateStartRequest(request); err != nil {
		return err
	}
	var result api.Briefing
	if err := templatesCall(ctx, call, &options, "brief.start", request, &result); err != nil {
		return err
	}
	role := api.RoleContext{Level: request.Level, Role: request.Role}
	life := request.LifeID
	if life == "" {
		var self api.Scope
		if err := templatesCall(ctx, call, &options, "identity.self", api.Empty{}, &self); err != nil {
			return err
		}
		if self.Config != call.Config ||
			!((self.Actor.Kind == "human" && self.Actor.LifeID == "") ||
				(self.Actor.Kind == "lane" || self.Actor.Kind == "worker") && templatesID.MatchString(string(self.Actor.LifeID))) {
			return templatesIntegrity("briefing identity response is missing its bound configuration or life")
		}
		if self.Actor.Kind == "lane" || self.Actor.Kind == "worker" {
			life = self.Actor.LifeID
		}
	}
	var task *api.BlobRef
	if life != "" {
		var lane api.Lane
		if err := templatesCall(ctx, call, &options, "lane.status", api.LifeRef{LifeID: life}, &lane); err != nil {
			return err
		}
		if lane.LifeID != life || lane.Level != request.Level || lane.Role != request.Role || !templatesBlob(lane.Task, "task") {
			return templatesIntegrity("briefing life or original task differs from the requested scope")
		}
		task = &lane.Task
	}
	return templatesPrintBrief(ctx, call, &options, role, task, result)
}

// runOrgValidate maps file/flag inputs to api.OrgValidateRequest, then calls org.validate.
func runOrgValidate(ctx context.Context, call Invocation) (resultErr error) {
	options, err := templatesParseFlags(call, "validate")
	if err != nil {
		return err
	}
	defer templatesClose(&options, &resultErr)
	request := api.OrgValidateRequest{Generation: api.Generation(options.generation)}
	if options.request != "" {
		if err := templatesReadRequest(&options, &request); err != nil {
			return err
		}
	}
	if err := templatesValidateOrgRequest(request); err != nil {
		return err
	}
	var result api.OrgValidation
	if err := templatesCall(ctx, call, &options, "org.validate", request, &result); err != nil {
		return err
	}
	if result.Valid != (len(result.Problems) == 0) {
		return templatesIntegrity("org validation result contradicts its problems")
	}
	if err := json.NewEncoder(call.Stdout).Encode(result); err != nil {
		return err
	}
	if !result.Valid {
		return templatesInvalid("org validation reported problems; retain the validation result")
	}
	return nil
}

// runOrgBootstrap maps file/flag inputs to api.BootstrapRequest, then calls org.bootstrap.
func runOrgBootstrap(ctx context.Context, call Invocation) (resultErr error) {
	options, err := templatesParseFlags(call, "bootstrap")
	if err != nil {
		return err
	}
	defer templatesClose(&options, &resultErr)
	var request api.BootstrapRequest
	if options.request != "" {
		if err := templatesReadRequest(&options, &request); err != nil {
			return err
		}
	} else {
		if !templatesID.MatchString(options.name) {
			return templatesInvalid("--name is required")
		}
		request.OrgName = options.name
		if options.contentRef != "" {
			if err := templatesReadJSON(options.contentRef, &request.SourceManifest); err != nil {
				return err
			}
		} else if options.proofFile != "" {
			return templatesInvalid("proof-bound bootstrap requires a committed --content-ref or --request-file")
		}
		if options.manifest != "" {
			data, err := templatesReadFile(options.manifest, api.MaxFrameBytes)
			if err != nil {
				return err
			}
			var manifest api.ObjectManifest
			if err := templates.DecodeJSON(data, &manifest); err != nil {
				return err
			}
			if manifest.Schema != "laneboss.objects.v2" {
				return templatesInvalid("--manifest must contain an ObjectManifest v2")
			}
			if options.contentRef != "" {
				if request.SourceManifest.Bytes != int64(len(data)) || request.SourceManifest.SHA256 != templatesHash(data) {
					return templatesIntegrity("--manifest bytes differ from the committed --content-ref")
				}
			} else {
				request.SourceManifest, err = templatesUpload(ctx, call, &options, "manifest", data)
				if err != nil {
					return err
				}
			}
		}
	}
	if err := templatesValidateBootstrapRequest(request); err != nil {
		return err
	}
	var result api.Operation
	if err := templatesCall(ctx, call, &options, "org.bootstrap", request, &result); err != nil {
		return err
	}
	if result.Error != nil {
		return result.Error
	}
	if !templatesID.MatchString(string(result.ID)) {
		return templatesIntegrity("bootstrap returned no operation identifier")
	}
	switch result.Status {
	case "pending", "running", "succeeded":
		return json.NewEncoder(call.Stdout).Encode(result)
	default:
		return templatesIntegrity("bootstrap returned a failed or unknown operation without its typed error")
	}
}

type templatesFlags struct {
	request, format, proofFile          string
	role, life, instance, grants, brief string
	name, manifest, contentRef          string
	taskRef                             string
	level                               int
	generation                          uint64
	rawRequest                          json.RawMessage
	socket                              *integrateSocket
	ownsSocket, sessionReady            bool
}

var templatesID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var templatesDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var templatesRequestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)

func templatesInvalid(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Use --request-file FILE with the frozen request body, or this command's file-backed flags.", Owner: "lb-v2-templates"}
}

func templatesIntegrity(message string) *api.Error {
	return &api.Error{Code: api.CodeIntegrity, Message: message,
		Instead: "Retain the inputs and service response, then report the integrity failure.", Owner: "lb-v2-templates"}
}

func templatesParseFlags(call Invocation, mode string) (templatesFlags, error) {
	var options templatesFlags
	if templatesValidators != nil {
		return options, templatesValidators
	}
	flags := flag.NewFlagSet(call.Path, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.request, "request-file", "", "exact request body file with template output verification")
	defaultFormat := "json"
	if mode == "render" || mode == "start" {
		defaultFormat = "markdown"
	}
	flags.StringVar(&options.format, "format", defaultFormat, "markdown or json")
	switch mode {
	case "render":
		flags.IntVar(&options.level, "level", 0, "selected level")
		flags.StringVar(&options.role, "role", "", "selected role")
		flags.StringVar(&options.instance, "instance-id", "", "recorded instance")
		flags.StringVar(&options.grants, "grant-set-id", "", "resolved grant set")
		flags.StringVar(&options.brief, "brief", "", "exact assigned task file")
		flags.StringVar(&options.taskRef, "task-ref", "", "committed active-turn task reference file")
	case "start":
		flags.IntVar(&options.level, "level", 0, "selected level")
		flags.StringVar(&options.role, "role", "", "selected role")
		flags.StringVar(&options.life, "life-id", "", "recorded life")
	case "validate":
		flags.Uint64Var(&options.generation, "generation", 0, "approved org generation")
	case "bootstrap":
		flags.StringVar(&options.name, "name", "", "new org name")
		flags.StringVar(&options.manifest, "manifest", "", "uploaded-source manifest file")
		flags.StringVar(&options.contentRef, "content-ref", "", "committed source-manifest reference file")
		flags.StringVar(&options.proofFile, "proof-file", "", "operation-bound proof reference")
	}
	seen := map[string]bool{}
	for index := 0; index < len(call.Args); index++ {
		word := call.Args[index]
		if !strings.HasPrefix(word, "--") || word == "--" {
			return options, templatesInvalid("positional or short template flags are not supported")
		}
		name := strings.SplitN(strings.TrimPrefix(word, "--"), "=", 2)[0]
		if seen[name] || flags.Lookup(name) == nil {
			return options, templatesInvalid("unknown or repeated template flag")
		}
		seen[name] = true
		if !strings.Contains(word, "=") {
			index++
			if index >= len(call.Args) || strings.HasPrefix(call.Args[index], "--") {
				return options, templatesInvalid("template flag is missing its value")
			}
		}
	}
	if err := flags.Parse(call.Args); err != nil || flags.NArg() != 0 {
		return options, templatesInvalid("invalid template flags")
	}
	if options.format != "json" && ((mode != "render" && mode != "start") || options.format != "markdown") {
		return options, templatesInvalid("unsupported template output format")
	}
	if seen["request-file"] && options.request == "" {
		return options, templatesInvalid("--request must name a file")
	}
	if options.request != "" {
		for name := range seen {
			if name != "request-file" && name != "format" && name != "proof-file" {
				return options, templatesInvalid("--request cannot be combined with request-body flags")
			}
		}
	}
	if options.proofFile != "" && call.ProofFile != "" {
		return options, templatesInvalid("duplicate proof file")
	}
	if options.proofFile == "" {
		options.proofFile = call.ProofFile
	}
	if !integrateConfigName.MatchString(call.Config) || call.Client != nil && call.Client.Options.Config != call.Config ||
		call.integrateSocket != nil && call.integrateSocket.options.Config != call.Config {
		return options, templatesInvalid("an explicit bound configuration and socket client are required")
	}
	options.socket = call.integrateSocket
	if call.Client == nil {
		if options.socket == nil {
			options.socket = &integrateSocket{options: client.Options{Config: call.Config}}
			options.ownsSocket = true
		}
	}
	return options, nil
}

func templatesValidateContext(value api.RoleContext) error {
	if value.Level < 3 || value.Level > 6 || value.Role == "" || !utf8.ValidString(value.Role) ||
		utf8.RuneCountInString(value.Role) > 128 || strings.TrimSpace(value.Role) != value.Role ||
		value.Role == "." || value.Role == ".." || strings.ContainsAny(value.Role, "/\\") ||
		strings.IndexFunc(value.Role, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		return templatesInvalid("a level in L3 through L6 and a safe role filename are required")
	}
	if value.InstanceID != "" && !templatesID.MatchString(string(value.InstanceID)) {
		return templatesInvalid("invalid instance identifier")
	}
	return nil
}

func templatesHash(data []byte) api.Digest { return api.Digest(fmt.Sprintf("%x", sha256.Sum256(data))) }

func templatesBlob(ref api.BlobRef, class string) bool {
	return templatesID.MatchString(string(ref.ID)) && templatesDigest.MatchString(string(ref.SHA256)) && ref.Bytes > 0 && ref.Bytes <= api.MaxObjectBytes && ref.Class == class
}

func templatesReadFile(path string, limit int64) (data []byte, err error) {
	if path == "" {
		return nil, templatesInvalid("an input file path is required")
	}
	file, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if openErr != nil {
		return nil, templatesInvalid("cannot open input file")
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = templatesIntegrity("input file could not be closed")
		}
	}()
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, templatesInvalid("input must be a bounded regular file")
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, templatesInvalid("cannot read complete input file")
	}
	if int64(len(data)) > limit {
		return nil, templatesInvalid("input exceeds its byte limit")
	}
	return data, nil
}

func templatesReadJSON(path string, destination any) error {
	data, err := templatesReadFile(path, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	return templates.DecodeJSON(data, destination)
}

func templatesReadRequest(options *templatesFlags, destination any) error {
	data, err := templatesReadFile(options.request, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	if err := templates.DecodeJSON(data, destination); err != nil {
		return err
	}
	options.rawRequest = bytes.Clone(data)
	return nil
}

func templatesClose(options *templatesFlags, resultErr *error) {
	if options.ownsSocket && options.socket != nil && options.socket.connection != nil {
		if err := options.socket.connection.Close(); err != nil {
			*resultErr = errors.Join(*resultErr, err)
		}
	}
}

func templatesCall(ctx context.Context, call Invocation, options *templatesFlags, method api.Method, params any, result any) error {
	data, err := json.Marshal(params)
	if err != nil {
		return templatesInvalid("request cannot be encoded")
	}
	if method == call.Method && len(options.rawRequest) != 0 {
		data = bytes.Clone(options.rawRequest)
	}
	var output bytes.Buffer
	rpc := call
	rpc.Method, rpc.Stdout, rpc.integrateSocket = method, &output, options.socket
	rpc.ProofFile = ""
	spec, exists := api.Methods[method]
	if !exists {
		return templatesInvalid("unknown template RPC method")
	}
	if method != call.Method {
		rpc.RequestID, rpc.IdempotencyKey = "", ""
		if spec.Mutation {
			var ordinal int64
			if chunk, ok := params.(api.BlobChunk); ok {
				ordinal = chunk.Offset
			}
			key, err := templatesSubKey(call, method, ordinal)
			if err != nil {
				return err
			}
			rpc.IdempotencyKey = key
		}
	}
	operationProof := spec.Mutation && !api.HumanSessionMethod(method)
	if operationProof {
		if method == call.Method {
			rpc.ProofFile = options.proofFile
		}
	} else if !options.sessionReady {
		rpc.ProofFile = options.proofFile
	}
	// InvokeRaw owns common envelope preparation, session-before-read and
	// response validation. Its shared socket is borrowed by every subcall.
	if method == call.Method && len(options.rawRequest) != 0 {
		err = rpc.InvokeRaw(ctx, data)
	} else {
		err = rpc.Invoke(ctx, params)
	}
	if err != nil {
		return err
	}
	if !operationProof && rpc.ProofFile != "" {
		options.sessionReady = true
	}
	return templates.DecodeJSON(output.Bytes(), result)
}

func templatesSubKey(call Invocation, method api.Method, ordinal int64) (api.ID, error) {
	if !templatesRequestKey.MatchString(string(call.IdempotencyKey)) {
		return "", templatesInvalid("upload requires an explicit retained --idempotency-key")
	}
	// The stage/offset identifies the same sub-operation on retry. Content is
	// deliberately excluded: changed bytes must conflict at the same key.
	data, err := json.Marshal([]any{"templates.upload.v2", call.Config, call.IdempotencyKey, method, ordinal})
	if err != nil {
		return "", templatesInvalid("upload retry key cannot be encoded")
	}
	return api.ID(templatesHash(data)), nil
}

func templatesUpload(ctx context.Context, call Invocation, options *templatesFlags, class string, data []byte) (api.BlobRef, error) {
	if len(data) == 0 || len(data) > api.MaxObjectBytes {
		return api.BlobRef{}, templatesInvalid("upload must contain bounded nonempty bytes")
	}
	digest := templatesHash(data)
	var upload api.BlobUpload
	if err := templatesCall(ctx, call, options, "blob.begin", api.BlobBeginRequest{Class: class, Bytes: int64(len(data)), SHA256: digest}, &upload); err != nil {
		return api.BlobRef{}, err
	}
	if !templatesID.MatchString(string(upload.ObjectID)) || upload.MaxChunkBytes <= 0 || upload.MaxChunkBytes > api.MaxChunkBytes {
		return api.BlobRef{}, templatesIntegrity("service returned an invalid upload reservation")
	}
	objectID := upload.ObjectID
	limit := upload.MaxChunkBytes
	for offset := 0; offset < len(data); {
		end := min(offset+limit, len(data))
		chunk := api.BlobChunk{ObjectID: objectID, Offset: int64(offset), Data: data[offset:end], SHA256: templatesHash(data[offset:end])}
		var next api.BlobUpload
		if err := templatesCall(ctx, call, options, "blob.chunk", chunk, &next); err != nil {
			return api.BlobRef{}, err
		}
		if next.ObjectID != objectID || next.MaxChunkBytes != limit {
			return api.BlobRef{}, templatesIntegrity("upload reservation changed during transfer")
		}
		offset = end
	}
	var ref api.BlobRef
	if err := templatesCall(ctx, call, options, "blob.commit", api.BlobCommitRequest{ObjectID: objectID, SHA256: digest}, &ref); err != nil {
		return api.BlobRef{}, err
	}
	if !templatesBlob(ref, class) || ref.ID != objectID || ref.SHA256 != digest || ref.Bytes != int64(len(data)) {
		return api.BlobRef{}, templatesIntegrity("committed upload differs from the exact file bytes")
	}
	return ref, nil
}

// The four run... functions above are frozen dispatch slots. All other private
// package declarations in this file use the templates prefix.
func templatesPrintBrief(ctx context.Context, call Invocation, options *templatesFlags,
	role api.RoleContext, task *api.BlobRef, briefing api.Briefing,
) error {
	if err := templates.ValidateBriefing(role, briefing); err != nil {
		return err
	}
	read := func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		var chunk api.BlobChunk
		if err := templatesCall(ctx, call, options, "blob.read", request, &chunk); err != nil {
			return api.BlobChunk{}, err
		}
		return chunk, nil
	}
	data, err := templates.ReadVerifiedBlob(ctx, briefing.Markdown, read)
	if err != nil {
		return err
	}
	if err := templates.VerifyPrompt(role, briefing, data); err != nil {
		return err
	}
	if task != nil {
		taskBytes, err := templates.ReadVerifiedBlob(ctx, *task, read)
		if err != nil {
			return err
		}
		if err := templates.VerifyTaskPrompt(role, briefing, *task, taskBytes, data); err != nil {
			return err
		}
	}
	if options.format == "json" {
		return json.NewEncoder(call.Stdout).Encode(briefing)
	}
	n, err := call.Stdout.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
