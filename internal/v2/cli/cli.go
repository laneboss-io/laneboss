// Package cli dispatches the v2 client commands and the service entry point.
// It imports no legacy state writer or hook protection engine.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"

	"laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/protocol"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/records"
)

type Invocation struct {
	Path             string
	Config           string
	Method           api.Method
	Args             []string
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	Client           *client.Client
	ProofFile        string
	SessionProofFile string
	RequestID        api.ID
	IdempotencyKey   api.ID
	integrateSocket  *integrateSocket
}

type integrateRPCClient interface {
	Call(context.Context, api.Request) (api.Response, error)
	Stream(context.Context, api.Request) (api.EventStream, error)
	Close() error
}

// One invocation, including uploads and human.session, owns one live socket.
// Copies of Invocation share this owner; an explicitly supplied Client is
// already open and remains owned by its caller.
type integrateSocket struct {
	options    client.Options
	connection integrateRPCClient
}

type integrateCommand struct {
	method api.Method
	run    func(context.Context, Invocation) error
}

// RegisterInputValidator is called by a feature adapter at initialization with
// the same local semantic validator used by its ergonomic command. It never
// grants service authority. Missing, duplicate or foreign registrations refuse.
func RegisterInputValidator(method api.Method, owner string, validate func(json.RawMessage) error) error {
	spec, exists := api.Methods[method]
	if !exists || owner != spec.Owner || validate == nil {
		return integrateInputError("input validator must belong to its catalog method")
	}
	integrateInputChecks.Lock()
	defer integrateInputChecks.Unlock()
	if integrateInputChecks.methods[method] != nil {
		return integrateInputError("duplicate input validator")
	}
	integrateInputChecks.methods[method] = validate
	delete(integrateNoFileInput, method)
	return nil
}

var integrateInputChecks = struct {
	sync.RWMutex
	methods map[api.Method]func(json.RawMessage) error
}{methods: map[api.Method]func(json.RawMessage) error{
	"records.get":      integrateInputCheck(records.ValidateGetInput),
	"records.query":    integrateInputCheck(records.ValidateQueryInput),
	"records.export":   integrateInputCheck(records.ValidateQueryInput),
	"records.append":   integrateInputCheck(records.ValidateAppendInput),
	"decisions.mutate": integrateInputCheck(records.ValidateDecisionInput),
	"records.import":   integrateInputCheck(records.ValidateImportInput),
	"box.launch":       integrateInputCheck(records.ValidateBoxLaunchInput),
	"box.run":          integrateInputCheck(records.ValidateBoxRunInput),
	"box.harvest":      integrateInputCheck(records.ValidateBoxHarvestInput),
	"box.end":          integrateInputCheck(records.ValidateBoxEndInput),
	"box.list":         integrateInputCheck(records.ValidateBoxListInput),
}}

func integrateInputCheck[Request any](validate func(Request) error) func(json.RawMessage) error {
	return func(raw json.RawMessage) error {
		var request Request
		if err := api.DecodeObject(raw, &request); err != nil {
			return err
		}
		return validate(request)
	}
}

func integrateValidateInput(method api.Method, raw json.RawMessage, required bool) error {
	integrateInputChecks.RLock()
	validate := integrateInputChecks.methods[method]
	integrateInputChecks.RUnlock()
	if validate != nil {
		// The validator may parse its input, but cannot replace the retained
		// request bytes or mutate the backing buffer sent to the socket.
		return validate(append(json.RawMessage(nil), raw...))
	}
	if required {
		return api.NotImplemented(api.Methods[method].Owner, string(method)+" input validator")
	}
	return nil // A typed ergonomic adapter performs its own semantic preflight.
}

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, stdin, stdout, stderr)
}

// RunContext lets the installed service receive shutdown through its normal
// cancellation path. Tests and library callers need not install signal hooks.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (exitCode int) {
	if handled, code := RunBootstrapEntry(ctx, args); handled {
		return code
	}
	if len(args) == 1 && args[0] == "--version" {
		_, version, err := protocol.Load()
		if err != nil {
			return integrateFailure(stderr, err)
		}
		return integrateEncoded(stdout, stderr, map[string]string{
			"program": identity.Program, "version": identity.Version,
			"protocol_version": version, "api_protocol": api.Protocol,
			"implementation": "v2-incomplete", "contract_revision": api.ContractRevision,
		})
	}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")) {
		return integrateHelp(stdout, stderr)
	}
	var selected integrateCommand
	path, consumed := "", 0
	for name, entry := range integrateCommands {
		words := strings.Split(name, " ")
		if len(words) <= consumed || len(words) > len(args) {
			continue
		}
		match := true
		for i, word := range words {
			if args[i] != word {
				match = false
				break
			}
		}
		if match {
			path, consumed, selected = name, len(words), entry
		}
	}
	if consumed == 0 {
		return integrateFailure(stderr, &api.Error{Code: api.CodeInvalid, Message: "unknown command", Instead: "Run laneboss --help."})
	}
	config, bindingFile, requestFile, proofFile, sessionProofFile := "", "", "", "", ""
	requestID, idempotencyKey := api.ID(""), api.ID("")
	seen := make(map[string]bool)
	var rest []string
	for i := consumed; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		if arg == "--help" || arg == "-h" {
			usage := "laneboss " + path + " --config NAME --request FILE [--binding FILE] [--proof FILE] [--idempotency-key ID] [--request-id ID]"
			if selected.method == "lane.start" || selected.method == "lane.adopt" {
				usage = "laneboss " + path + " --config NAME --request FILE [--binding FILE] [--session-proof FILE] [--idempotency-key ID] [--request-id ID]"
			}
			if path == "org hook" {
				usage = "laneboss org hook --config NAME (hook adapter input; raw --request is unsupported)"
			}
			if path == "serve" {
				usage = "laneboss serve --config NAME --installation FILE [--binding FILE]"
			}
			if path == "human session" {
				usage = "laneboss human session --config NAME --proof FILE [--binding FILE] [--flow FILE] [--wait 120s]"
			}
			if selected.method == "" && path != "serve" {
				usage = "laneboss " + path + " --config NAME (installed service job only)"
			}
			return integrateEncoded(stdout, stderr, map[string]string{
				"command": path, "method": string(selected.method),
				"status": "v2-incomplete", "usage": usage,
			})
		}
		if arg == "--config" || strings.HasPrefix(arg, "--config=") {
			if seen["--config"] {
				return integrateFailure(stderr, &api.Error{Code: api.CodeInvalid, Message: "duplicate configuration", Instead: "Pass one explicit --config NAME."})
			}
			seen["--config"] = true
			if arg == "--config" {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return integrateFailure(stderr, &api.Error{Code: api.CodeInvalid, Message: "missing configuration", Instead: "Pass --config NAME."})
				}
				config = args[i]
			} else {
				config = strings.TrimPrefix(arg, "--config=")
			}
			continue
		}
		name, value, inline := strings.Cut(arg, "=")
		if name == "--binding" || name == "--binding-file" || name == "--request" || name == "--proof" || name == "--session-proof" || name == "--request-id" || name == "--idempotency-key" {
			if name == "--binding-file" {
				name = "--binding"
			}
			if seen[name] {
				return integrateFailure(stderr, integrateInputError("duplicate common option"))
			}
			seen[name] = true
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return integrateFailure(stderr, integrateInputError("common option requires a value"))
				}
				value = args[i]
			}
			if value == "" {
				return integrateFailure(stderr, integrateInputError("common option requires a nonempty value"))
			}
			switch name {
			case "--binding":
				bindingFile = value
			case "--request":
				requestFile = value
			case "--proof":
				proofFile = value
			case "--session-proof":
				sessionProofFile = value
			case "--request-id":
				requestID = api.ID(value)
			case "--idempotency-key":
				idempotencyKey = api.ID(value)
			}
			continue
		}
		rest = append(rest, arg)
	}
	if sessionProofFile != "" && (proofFile != "" || selected.method != "lane.start" && selected.method != "lane.adopt") {
		return integrateFailure(stderr, integrateInputError("--session-proof requires a root spawn without --proof"))
	}
	if config == "" {
		return integrateFailure(stderr, &api.Error{Code: api.CodeInvalid, Message: "explicit configuration required", Instead: "Pass --config NAME without changing the active binding."})
	}
	if !integrateConfigName.MatchString(config) {
		return integrateFailure(stderr, integrateInputError("invalid configuration name"))
	}
	// Read exactly the binding variable. Never clear/change it or print either
	// name in a conflict diagnostic; a conflicting command has no side effects.
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" && bound != config {
		return integrateFailure(stderr, &api.Error{Code: api.CodeConflict, Message: "explicit configuration conflicts with the active session binding", Instead: "Keep this session's binding; use a separate isolated process for another configuration."})
	}
	if bindingFile != "" && !filepath.IsAbs(bindingFile) {
		return integrateFailure(stderr, integrateInputError("binding file must be absolute"))
	}
	socket := &integrateSocket{options: client.Options{Config: config, BindingFile: bindingFile}}
	defer func() {
		if socket.connection != nil {
			if err := socket.connection.Close(); err != nil {
				closeCode := integrateFailure(stderr, err)
				if exitCode == 0 {
					exitCode = closeCode
				}
			}
		}
	}()
	call := Invocation{
		Path: path, Config: config, Method: selected.method, Args: rest,
		Stdin: stdin, Stdout: stdout, Stderr: stderr,
		integrateSocket: socket,
		ProofFile:       proofFile, SessionProofFile: sessionProofFile, RequestID: requestID, IdempotencyKey: idempotencyKey,
	}
	if requestFile != "" {
		if path == "org hook" {
			return integrateFailure(stderr, &api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-policy",
				Message: "org hook does not support the raw request-file form",
				Instead: "Use org hook's decision-aware adapter without --request; a deny must produce a nonzero exit."})
		}
		if len(rest) != 0 || selected.method == "" {
			return integrateFailure(stderr, integrateInputError("--request accepts only an exact RPC body and common options"))
		}
		if err := call.invokeFile(ctx, requestFile); err != nil {
			return integrateFailure(stderr, err)
		}
		return 0
	}
	if err := selected.run(ctx, call); err != nil {
		return integrateFailure(stderr, err)
	}
	return 0
}

func integrateEncoded(stdout, stderr io.Writer, value any) int {
	if err := json.NewEncoder(stdout).Encode(value); err != nil {
		return integrateFailure(stderr, err)
	}
	return 0
}

func integrateHelp(stdout, stderr io.Writer) int {
	names := make([]string, 0, len(integrateCommands))
	for name := range integrateCommands {
		names = append(names, name)
	}
	sort.Strings(names)
	if _, err := fmt.Fprintln(stdout, "Laneboss v2 integration in progress. State commands require --config NAME and an installed service; unfinished operations fail explicitly."); err != nil {
		return integrateFailure(stderr, err)
	}
	for _, name := range names {
		if _, err := fmt.Fprintln(stdout, "  "+name); err != nil {
			return integrateFailure(stderr, err)
		}
	}
	return 0
}

var integrateConfigName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func integrateInputError(message string) *api.Error {
	return &api.Error{Code: api.CodeInvalid, Message: message, Instead: "Use the documented file-backed request and one explicit configuration."}
}

// ReadInput reads only a client-local file; no path is forwarded to the service.
func ReadInput(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, integrateInputError("cannot open input file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, integrateInputError("input must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, integrateInputError("cannot read bounded input file")
	}
	return data, nil
}

func integrateNewRequestID() (api.ID, error) { return client.NewRequestID() }

// Invoke is the shared typed socket path for ergonomic feature handlers.
func (call Invocation) Invoke(ctx context.Context, params any) error {
	raw, err := json.Marshal(params)
	if err != nil {
		return integrateInputError("cannot encode typed request")
	}
	return call.invokeRaw(ctx, raw, false)
}

// InvokeRaw supports the exact file form for every catalog method. It never
// dispatches to a legacy handler or opens a state/configuration database.
func (call Invocation) InvokeRaw(ctx context.Context, raw json.RawMessage) (resultErr error) {
	return call.invokeRaw(ctx, raw, true)
}

func (call Invocation) invokeFile(ctx context.Context, path string) error {
	raw, err := ReadInput(path, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	return call.InvokeRaw(ctx, raw)
}

func (call Invocation) invokeRaw(ctx context.Context, raw json.RawMessage, requireValidator bool) (resultErr error) {
	spec, exists := api.Methods[call.Method]
	if !exists {
		return integrateInputError("command has no typed RPC method")
	}
	params := reflect.New(spec.Request).Interface()
	if err := api.DecodeObject(raw, params); err != nil {
		return err
	}
	if err := integrateValidateInput(call.Method, raw, requireValidator); err != nil {
		return err
	}
	if err := integrateValidateAlias(call, params); err != nil {
		return err
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion,
		Config: call.Config, Method: call.Method, Params: raw,
		RequestID: call.RequestID, IdempotencyKey: call.IdempotencyKey}
	var sessionRequest *api.Request
	if call.SessionProofFile != "" {
		prelude, err := call.identitySpawnSession()
		if err != nil {
			return err
		}
		sessionRequest = &prelude
	}
	if call.ProofFile != "" {
		rawProof, err := ReadInput(call.ProofFile, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		var proof api.ProofRef
		if err := api.DecodeObject(rawProof, &proof); err != nil {
			return err
		}
		if !spec.Mutation || api.HumanSessionMethod(call.Method) {
			session, err := integrateSessionRequest(call.Config, proof)
			if err != nil {
				return err
			}
			sessionRequest = &session
		} else {
			request.Proof = &proof
		}
	}
	prototype := call.Client
	if prototype == nil {
		options := client.Options{Config: call.Config}
		if call.integrateSocket != nil {
			options = call.integrateSocket.options
		}
		prototype = &client.Client{Options: options}
	}
	prepared, err := prototype.PrepareRequest(request)
	if err != nil {
		return err
	}
	request = prepared
	var connection integrateRPCClient = call.Client
	if call.Client == nil {
		socket := call.integrateSocket
		if socket == nil {
			socket = &integrateSocket{options: prototype.Options}
			defer func() {
				if socket.connection != nil {
					if err := socket.connection.Close(); err != nil {
						resultErr = errors.Join(resultErr, err)
					}
				}
			}()
		}
		if socket.connection == nil {
			opened, err := client.Open(ctx, socket.options)
			if err != nil {
				return err
			}
			socket.connection = opened
		}
		connection = socket.connection
	}
	if sessionRequest != nil {
		response, err := connection.Call(ctx, *sessionRequest)
		if err != nil {
			return err
		}
		sessionCall := call
		sessionCall.Method, sessionCall.Stdout = "human.session", io.Discard
		if err := sessionCall.integrateWriteResponse(*sessionRequest, response); err != nil {
			return err
		}
		if call.SessionProofFile != "" {
			if err := call.identityCheckPrelude(ctx, connection); err != nil {
				return err
			}
		}
	}
	streaming := call.Method == "lane.attach"
	if integrateFollow, ok := params.(*api.EventTailRequest); ok {
		streaming = integrateFollow.Follow
	}
	if streaming {
		return call.integrateFollow(ctx, connection, request, params)
	}
	response, err := connection.Call(ctx, request)
	if err != nil {
		return err
	}
	return call.integrateWriteResponse(request, response)
}

func (call Invocation) integrateWriteResponse(request api.Request, response api.Response) error {
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != request.RequestID || (response.Error == nil) == (len(response.Result) == 0) {
		return &api.Error{Code: api.CodeIntegrity, Message: "invalid service response envelope", Instead: "Preserve the response and repair the matched client/service installation."}
	}
	if response.Error != nil {
		return response.Error
	}
	result := reflect.New(api.Methods[call.Method].Response).Interface()
	if err := api.DecodeObject(response.Result, result); err != nil {
		return &api.Error{Code: api.CodeIntegrity, Message: "service result does not match the typed method", Instead: "Repair the service; no empty success or local fallback is permitted."}
	}
	if _, err := call.Stdout.Write(append(append([]byte(nil), response.Result...), '\n')); err != nil {
		return err
	}
	return nil
}

func (call Invocation) integrateFollow(ctx context.Context, connection integrateRPCClient, request api.Request, params any) (resultErr error) {
	stream, err := connection.Stream(ctx, request)
	if err != nil {
		return err
	}
	defer func() {
		if err := stream.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	initial, ok := stream.(api.ResponseStream)
	if !ok {
		return api.NotImplemented("lb-v2-service", "client stream initial response")
	}
	response := initial.Initial()
	if err := call.integrateWriteResponse(request, response); err != nil {
		return err
	}
	tail, isTail := params.(*api.EventTailRequest)
	matched := false
	if isTail {
		var page api.EventPage
		if err := api.DecodeObject(response.Result, &page); err != nil {
			return err
		}
		for _, event := range page.Events {
			matched = matched || integrateSelectedEnd(event, *tail)
		}
	}
	for index := uint64(1); ; index++ {
		frame, err := stream.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return &api.Error{Code: api.CodeUnavailable, Message: "stream disconnected before its end frame", Instead: "Resume from the last authorized cursor; a disconnect is not completion."}
			}
			return err
		}
		if frame.RequestID != request.RequestID || frame.Index != index || frame.End && (frame.Event != nil || frame.Chunk != nil) || frame.Error != nil && (frame.Event != nil || frame.Chunk != nil) {
			return &api.Error{Code: api.CodeIntegrity, Message: "invalid stream correlation or frame shape", Instead: "Retain the stream evidence and repair the service transport."}
		}
		if frame.Error != nil {
			return frame.Error
		}
		if !frame.End && (frame.Event == nil) == (frame.Chunk == nil) {
			return &api.Error{Code: api.CodeIntegrity, Message: "stream data frame requires exactly one payload", Instead: "Repair the typed stream producer."}
		}
		if isTail && frame.Event != nil {
			matched = matched || integrateSelectedEnd(*frame.Event, *tail)
		}
		if frame.End && isTail && tail.Until != "" && !matched {
			return &api.Error{Code: api.CodeIntegrity, Message: "stream ended without the selected authentic run event", Instead: "Inspect the selected life/run and resume from its cursor."}
		}
		if err := json.NewEncoder(call.Stdout).Encode(frame); err != nil {
			return err
		}
		if frame.End {
			return nil
		}
	}
}

func integrateSessionRequest(config string, proof api.ProofRef) (api.Request, error) {
	if proof.ID == "" {
		return api.Request{}, integrateInputError("human read requires a proof for human.session")
	}
	key, err := integrateUploadKey(api.ID(config+"\x00"+string(proof.ID)), "human.session")
	if err != nil {
		return api.Request{}, err
	}
	return client.PrepareRequest(api.Request{Config: config, Method: "human.session",
		Params: json.RawMessage(`{}`), IdempotencyKey: key, Proof: &proof})
}

func integrateSelectedEnd(event api.Event, request api.EventTailRequest) bool {
	return request.Until != "" && event.Kind == request.Until && event.LifeID == request.LifeID &&
		event.Run == request.Run && event.Seq > request.Since && event.Origin == "service"
}

func integrateFailure(stderr io.Writer, err error) int {
	var typed *api.Error
	if !errors.As(err, &typed) {
		typed = &api.Error{Code: api.CodeIntegrity, Message: "internal client failure", Instead: "Retain the evidence and report to the supervisor."}
	}
	if encodeErr := json.NewEncoder(stderr).Encode(typed); encodeErr != nil {
		return 70
	}
	switch typed.Code {
	case api.CodeNotImplemented, api.CodeUnavailable, api.CodeUnsupported, api.CodePrerequisite:
		return 69
	case api.CodeIntegrity:
		return 3
	case api.CodeDeadline, api.CodeContainmentUnknown:
		return 75
	default:
		return 2
	}
}
