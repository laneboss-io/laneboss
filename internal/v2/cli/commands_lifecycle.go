package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/lifecycle"
)

// New lane-local declarations use lbV2Lifecycle. The runLane*/runEventTail
// functions below are the pre-existing integration-owned dispatch bindings.
var lbV2LifecycleValidators = lbV2LifecycleRegisterValidators()

func lbV2LifecycleRegisterValidators() []api.Method {
	methods := []api.Method{"lane.start", "lane.adopt", "lane.resume", "lane.turn",
		"lane.stop", "lane.mark", "lane.review", "lane.clean", "lane.archive", "lane.status",
		"lane.list", "lane.check", "lane.loop", "lane.attach", "lane.input", "event.tail"}
	for _, method := range methods {
		if err := RegisterInputValidator(method, "lb-v2-lifecycle", func(raw json.RawMessage) error {
			return lifecycle.ValidateInput(method, raw)
		}); err != nil {
			panic(err)
		}
	}
	return methods
}

type lbV2LifecycleFlags struct{ values map[string]*string }

func lbV2LifecycleInvalid(message string) error {
	return &api.Error{Code: api.CodeInvalid, Message: message,
		Instead: "Correct the retained lifecycle request file or flags.",
		Owner:   "lb-v2-lifecycle"}
}

func lbV2LifecycleIntegrity(message string) error {
	return &api.Error{Code: api.CodeIntegrity, Message: message,
		Instead: "Retain the evidence and repair the service connection.",
		Owner:   "lb-v2-lifecycle"}
}

func lbV2LifecycleNames(method api.Method) string {
	const target = "life run lane "
	const cas = target + "generation "
	switch method {
	case "lane.start":
		return "lane project level role driver profile-grant model effort brief " +
			"grants budget-file root-ticket policy-generation"
	case "lane.resume":
		return cas + "message budget-file"
	case "lane.stop":
		return cas + "reason"
	case "lane.mark":
		return cas + "state review"
	case "lane.clean":
		return cas + "archive-receipt"
	case "lane.archive":
		return cas
	case "lane.status", "lane.check":
		return target
	case "lane.list":
		return "life cursor limit"
	case "lane.attach":
		return target + "cursor mode"
	case "event.tail":
		return target + "since cursor follow until deadline-ms"
	default:
		return ""
	}
}

func lbV2LifecycleParse(call Invocation) (*lbV2LifecycleFlags, error) {
	set := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	options := &lbV2LifecycleFlags{values: map[string]*string{}}
	var follow bool
	for _, name := range strings.Fields("request proof request-id idempotency-key format " + lbV2LifecycleNames(call.Method)) {
		if name == "follow" {
			set.BoolVar(&follow, name, false, "")
			continue
		}
		initial := ""
		switch name {
		case "format":
			initial = "json"
		case "limit":
			initial = "100"
		case "since":
			initial = "0"
		case "deadline-ms":
			initial = "60000"
		}
		options.values[name] = set.String(name, initial, "")
	}
	if err := set.Parse(call.Args); err != nil || set.NArg() != 0 {
		return nil, lbV2LifecycleInvalid("unknown, malformed or positional lifecycle argument")
	}
	seen := map[string]bool{}
	for i := 0; i < len(call.Args); i++ {
		arg := call.Args[i]
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") {
			name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
			if seen[name] {
				return nil, lbV2LifecycleInvalid("duplicate lifecycle flag")
			}
			seen[name] = true
			if !strings.Contains(arg, "=") && name != "follow" {
				i++
			}
		}
	}
	value := strconv.FormatBool(follow)
	options.values["follow"] = &value
	if options.lbV2LifecycleGet("format") != "json" && options.lbV2LifecycleGet("format") != "jsonl" {
		return nil, lbV2LifecycleInvalid("lifecycle output format must be json or jsonl")
	}
	if options.lbV2LifecycleGet("request") != "" {
		conflict := false
		set.Visit(func(value *flag.Flag) {
			switch value.Name {
			case "request", "proof", "request-id", "idempotency-key", "format":
			default:
				conflict = true
			}
		})
		if conflict {
			return nil, lbV2LifecycleInvalid("request file cannot have feature overrides")
		}
	}
	return options, nil
}

func (options *lbV2LifecycleFlags) lbV2LifecycleGet(name string) string {
	if value := options.values[name]; value != nil {
		return *value
	}
	return ""
}

func (options *lbV2LifecycleFlags) lbV2LifecycleNumber(name string) (uint64, error) {
	value, err := strconv.ParseUint(options.lbV2LifecycleGet(name), 10, 64)
	if err != nil || value > 1<<53-1 {
		return 0, lbV2LifecycleInvalid("missing or out-of-range lifecycle integer")
	}
	return value, nil
}

func lbV2LifecycleFile(path string, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, lbV2LifecycleInvalid("required lifecycle input file missing")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, lbV2LifecycleInvalid("cannot open lifecycle input file")
	}
	info, statErr := file.Stat()
	var data []byte
	var readErr error
	if statErr == nil && info.Mode().IsRegular() && info.Size() <= maximum {
		data, readErr = io.ReadAll(io.LimitReader(file, maximum+1))
	} else {
		readErr = lbV2LifecycleInvalid("input must be a bounded regular file")
	}
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || int64(len(data)) > maximum {
		return nil, lbV2LifecycleInvalid("cannot read complete bounded lifecycle input")
	}
	return data, nil
}

func lbV2LifecycleReadJSON(path string, destination any) error {
	data, err := lbV2LifecycleFile(path, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	return lifecycle.DecodeRequest(data, destination)
}

func lbV2LifecycleID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range []byte(value) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func lbV2LifecycleHash(data []byte) api.Digest {
	value := sha256.Sum256(data)
	return api.Digest(hex.EncodeToString(value[:]))
}

func lbV2LifecycleInvocation(call Invocation, options *lbV2LifecycleFlags) (Invocation, error) {
	if call.Config == "" {
		return Invocation{}, lbV2LifecycleInvalid("explicit matching client configuration required")
	}
	if options != nil {
		for _, field := range []struct {
			name  string
			value *api.ID
		}{{"request-id", &call.RequestID}, {"idempotency-key", &call.IdempotencyKey}} {
			if value := options.lbV2LifecycleGet(field.name); value != "" {
				if *field.value != "" && *field.value != api.ID(value) {
					return Invocation{}, lbV2LifecycleInvalid("conflicting common request identity")
				}
				*field.value = api.ID(value)
			}
		}
		if proof := options.lbV2LifecycleGet("proof"); proof != "" {
			if call.ProofFile != "" && call.ProofFile != proof {
				return Invocation{}, lbV2LifecycleInvalid("conflicting common proof file")
			}
			call.ProofFile = proof
		}
	}
	return call, nil
}

func lbV2LifecycleUploadKey(call Invocation, phase string) (api.ID, error) {
	if !lbV2LifecycleID(string(call.IdempotencyKey)) || len(call.IdempotencyKey) < 22 {
		return "", lbV2LifecycleInvalid("mutation requires a retained --idempotency-key")
	}
	// Stable subkeys belong to the retained parent, never to new input bytes.
	// Changed bytes with that same key must conflict at blob.begin/chunk.
	return api.ID(lbV2LifecycleHash([]byte("lifecycle-upload\x00" + call.Config + "\x00" +
		string(call.IdempotencyKey) + "\x00" + phase))), nil
}

func lbV2LifecycleCallRaw[R any](ctx context.Context, call Invocation, method api.Method,
	params []byte, options *lbV2LifecycleFlags, primary bool) (R, error) {
	var result R
	prepared, err := lbV2LifecycleInvocation(call, options)
	if err != nil {
		return result, err
	}
	prepared.Method = method
	if !primary {
		prepared.RequestID = ""
		if api.Methods[method].Mutation || api.Methods[call.Method].Mutation {
			prepared.ProofFile = ""
		}
		prepared.Path = strings.ReplaceAll(string(method), ".", " ")
		prepared.IdempotencyKey = ""
		if api.Methods[method].Mutation {
			phase := string(method)
			if method == "blob.chunk" {
				var chunk api.BlobChunk
				if err := lifecycle.DecodeRequest(params, &chunk); err != nil {
					return result, err
				}
				phase += ":" + strconv.FormatInt(chunk.Offset, 10)
			}
			prepared.IdempotencyKey, err = lbV2LifecycleUploadKey(call, phase)
			if err != nil {
				return result, err
			}
		}
	}
	var output bytes.Buffer
	prepared.Stdout = &output
	// The exact primary file keeps its raw invocation. Typed subcalls retain
	// their own adapter preflight and share the same socket and upload keys.
	if primary {
		err = prepared.InvokeRaw(ctx, params)
	} else {
		err = prepared.Invoke(ctx, json.RawMessage(params))
	}
	if err != nil {
		return result, err
	}
	if err := lifecycle.DecodeRequest(bytes.TrimSpace(output.Bytes()), &result); err != nil {
		return result, lbV2LifecycleIntegrity("invalid typed lifecycle result")
	}
	return result, nil
}

func lbV2LifecycleCall[Q, R any](ctx context.Context, call Invocation, method api.Method,
	request Q) (R, error) {
	var result R
	params, err := json.Marshal(request)
	if err != nil {
		return result, lbV2LifecycleInvalid("cannot encode lifecycle request")
	}
	return lbV2LifecycleCallRaw[R](ctx, call, method, params, nil, false)
}

func lbV2LifecycleUpload(ctx context.Context, call Invocation, path string) (api.BlobRef, error) {
	if call.ProofFile != "" {
		return api.BlobRef{}, lbV2LifecycleInvalid("an operation proof requires committed input references in --request")
	}
	if _, err := lbV2LifecycleUploadKey(call, "blob.begin"); err != nil {
		return api.BlobRef{}, err
	}
	data, err := lbV2LifecycleFile(path, api.MaxObjectBytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	digest := lbV2LifecycleHash(data)
	upload, err := lbV2LifecycleCall[api.BlobBeginRequest, api.BlobUpload](ctx, call, "blob.begin",
		api.BlobBeginRequest{Class: "task", Bytes: int64(len(data)), SHA256: digest})
	if err != nil {
		return api.BlobRef{}, err
	}
	if !lbV2LifecycleID(string(upload.ObjectID)) || upload.MaxChunkBytes < 1 || upload.MaxChunkBytes > api.MaxChunkBytes {
		return api.BlobRef{}, lbV2LifecycleIntegrity("invalid lifecycle upload lease")
	}
	for offset := 0; offset < len(data); {
		end := min(len(data), offset+upload.MaxChunkBytes)
		chunk := api.BlobChunk{ObjectID: upload.ObjectID, Offset: int64(offset),
			Data: data[offset:end], SHA256: lbV2LifecycleHash(data[offset:end])}
		ack, err := lbV2LifecycleCall[api.BlobChunk, api.BlobUpload](ctx, call, "blob.chunk", chunk)
		if err != nil {
			return api.BlobRef{}, err
		}
		if ack.ObjectID != upload.ObjectID {
			return api.BlobRef{}, lbV2LifecycleIntegrity("upload acknowledgment changed object identity")
		}
		offset = end
	}
	ref, err := lbV2LifecycleCall[api.BlobCommitRequest, api.BlobRef](ctx, call, "blob.commit",
		api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: digest})
	if err != nil {
		return api.BlobRef{}, err
	}
	if ref.ID != upload.ObjectID || ref.SHA256 != digest ||
		ref.Bytes != int64(len(data)) || ref.Class != "task" {
		return api.BlobRef{}, lbV2LifecycleIntegrity("committed input differs from exact source bytes")
	}
	return ref, nil
}

func lbV2LifecycleTarget(ctx context.Context, call Invocation, options *lbV2LifecycleFlags) (api.LifeRef, error) {
	if options.lbV2LifecycleGet("life") != "" {
		run, err := options.lbV2LifecycleNumber("run")
		if err != nil || run == 0 || !lbV2LifecycleID(options.lbV2LifecycleGet("life")) || options.lbV2LifecycleGet("lane") != "" {
			return api.LifeRef{}, lbV2LifecycleInvalid("select one explicit life and positive run")
		}
		return api.LifeRef{LifeID: api.ID(options.lbV2LifecycleGet("life")), Run: api.RunNumber(run)}, nil
	}
	if options.lbV2LifecycleGet("lane") == "" {
		return api.LifeRef{}, lbV2LifecycleInvalid("explicit life/run or lane required")
	}
	var candidate *api.Lane
	query := api.ListRequest{Limit: 200}
	for {
		page, err := lbV2LifecycleCall[api.ListRequest, api.LanePage](ctx, call, "lane.list", query)
		if err != nil {
			return api.LifeRef{}, err
		}
		for _, lane := range page.Lanes {
			if lane.Name == options.lbV2LifecycleGet("lane") && !lane.Cleaned {
				if candidate != nil {
					return api.LifeRef{}, lbV2LifecycleInvalid("ambiguous lane; select its immutable life")
				}
				copy := lane
				candidate = &copy
			}
		}
		if page.Cursor == "" {
			break
		}
		if page.Cursor == query.Cursor {
			return api.LifeRef{}, lbV2LifecycleIntegrity("lane cursor did not advance")
		}
		query.Cursor = page.Cursor
	}
	if candidate == nil {
		return api.LifeRef{}, &api.Error{Code: api.CodeNotFound,
			Message: "no visible active lane has that name", Instead: "Select a retained immutable life."}
	}
	run := candidate.Run
	if options.lbV2LifecycleGet("run") != "" {
		value, err := options.lbV2LifecycleNumber("run")
		if err != nil || value == 0 {
			return api.LifeRef{}, lbV2LifecycleInvalid("invalid selected run")
		}
		run = api.RunNumber(value)
	}
	return api.LifeRef{LifeID: candidate.LifeID, Run: run}, nil
}

func lbV2LifecycleBuild(ctx context.Context, call Invocation, options *lbV2LifecycleFlags, destination any) error {
	switch request := destination.(type) {
	case *api.StartRequest:
		level, err := options.lbV2LifecycleNumber("level")
		if err != nil || level < 3 || level > 6 {
			return lbV2LifecycleInvalid("invalid child level")
		}
		generation, err := options.lbV2LifecycleNumber("policy-generation")
		if err != nil || generation == 0 {
			return lbV2LifecycleInvalid("explicit policy generation required")
		}
		*request = api.StartRequest{Lane: options.lbV2LifecycleGet("lane"), ProjectID: api.ID(options.lbV2LifecycleGet("project")),
			Level: int(level), Role: options.lbV2LifecycleGet("role"), Driver: api.Driver(options.lbV2LifecycleGet("driver")),
			ProfileGrantID: api.ID(options.lbV2LifecycleGet("profile-grant")), Model: options.lbV2LifecycleGet("model"),
			Effort: options.lbV2LifecycleGet("effort"), RootTicketID: api.ID(options.lbV2LifecycleGet("root-ticket")),
			ExpectedPolicyGeneration: api.Generation(generation)}
		if err := lbV2LifecycleReadJSON(options.lbV2LifecycleGet("grants"), &request.Grants); err != nil {
			return err
		}
		if err := lbV2LifecycleReadJSON(options.lbV2LifecycleGet("budget-file"), &request.Budget); err != nil {
			return err
		}
		request.Task, err = lbV2LifecycleUpload(ctx, call, options.lbV2LifecycleGet("brief"))
		return err
	case *api.ListRequest:
		limit, err := options.lbV2LifecycleNumber("limit")
		if err != nil || limit < 1 || limit > 200 {
			return lbV2LifecycleInvalid("list limit must be from 1 through 200")
		}
		*request = api.ListRequest{LifeID: api.ID(options.lbV2LifecycleGet("life")), Cursor: options.lbV2LifecycleGet("cursor"), Limit: int(limit)}
		return nil
	case *api.AdoptRequest, *api.TurnRequest, *api.ReviewRequest, *api.LoopRequest, *api.AttachInputRequest:
		return lbV2LifecycleInvalid("this lifecycle operation requires a complete request file")
	}
	target, err := lbV2LifecycleTarget(ctx, call, options)
	if err != nil {
		return err
	}
	if request, ok := destination.(*api.LifeRef); ok {
		*request = target
		return nil
	}
	if request, ok := destination.(*api.AttachRequest); ok {
		*request = api.AttachRequest{Target: target, Cursor: options.lbV2LifecycleGet("cursor"), Mode: options.lbV2LifecycleGet("mode")}
		return nil
	}
	if request, ok := destination.(*api.EventTailRequest); ok {
		since, err := options.lbV2LifecycleNumber("since")
		if err != nil {
			return err
		}
		deadline, err := options.lbV2LifecycleNumber("deadline-ms")
		if err != nil {
			return err
		}
		*request = api.EventTailRequest{LifeID: target.LifeID, Run: target.Run,
			Since: api.Sequence(since), Cursor: options.lbV2LifecycleGet("cursor"),
			Follow: options.lbV2LifecycleGet("follow") == "true", Until: api.EventKind(options.lbV2LifecycleGet("until")),
			DeadlineMS: int64(deadline)}
		return nil
	}
	generation, err := options.lbV2LifecycleNumber("generation")
	if err != nil || generation == 0 {
		return lbV2LifecycleInvalid("explicit positive life generation required")
	}
	switch request := destination.(type) {
	case *api.ResumeRequest:
		*request = api.ResumeRequest{Target: target, ExpectedGeneration: api.Generation(generation)}
		if err := lbV2LifecycleReadJSON(options.lbV2LifecycleGet("budget-file"), &request.Budget); err != nil {
			return err
		}
		request.Message, err = lbV2LifecycleUpload(ctx, call, options.lbV2LifecycleGet("message"))
		return err
	case *api.StopRequest:
		*request = api.StopRequest{Target: target, ExpectedGeneration: api.Generation(generation)}
		request.Reason, err = lbV2LifecycleUpload(ctx, call, options.lbV2LifecycleGet("reason"))
		return err
	case *api.MarkRequest:
		*request = api.MarkRequest{Target: target, ExpectedGeneration: api.Generation(generation), State: options.lbV2LifecycleGet("state")}
		return lbV2LifecycleReadJSON(options.lbV2LifecycleGet("review"), &request.Review)
	case *api.ArchiveRequest:
		*request = api.ArchiveRequest{Target: target, ExpectedGeneration: api.Generation(generation)}
	case *api.CleanRequest:
		*request = api.CleanRequest{Target: target, ExpectedGeneration: api.Generation(generation),
			ArchiveReceiptID: api.ID(options.lbV2LifecycleGet("archive-receipt"))}
	default:
		return lbV2LifecycleInvalid("unsupported lifecycle flag conversion")
	}
	return nil
}

func lbV2LifecycleRun[Q, R any](ctx context.Context, call Invocation) error {
	options, err := lbV2LifecycleParse(call)
	if err != nil {
		return err
	}
	call, err = lbV2LifecycleInvocation(call, options)
	if err != nil {
		return err
	}
	if api.Methods[call.Method].Mutation &&
		(!lbV2LifecycleID(string(call.IdempotencyKey)) || len(call.IdempotencyKey) < 22) {
		return lbV2LifecycleInvalid("mutation requires a retained --idempotency-key")
	}
	var request Q
	var params []byte
	if options.lbV2LifecycleGet("request") != "" {
		params, err = lbV2LifecycleFile(options.lbV2LifecycleGet("request"), api.MaxFrameBytes)
		if err != nil {
			return err
		}
	} else {
		if err := lbV2LifecycleBuild(ctx, call, options, &request); err != nil {
			return err
		}
		params, err = json.Marshal(request)
		if err != nil {
			return lbV2LifecycleInvalid("cannot encode lifecycle input")
		}
	}
	if err := lifecycle.DecodeRequest(params, &request); err != nil {
		return err
	}
	if selection, ok := any(request).(api.EventTailRequest); ok && selection.Follow {
		return lbV2LifecycleStream(ctx, call, options, params, selection)
	}
	result, err := lbV2LifecycleCallRaw[R](ctx, call, call.Method, params, options, true)
	if err != nil {
		return err
	}
	return json.NewEncoder(call.Stdout).Encode(result)
}

type lbV2LifecycleSink struct {
	call        Invocation
	selection   api.EventTailRequest
	requestID   api.ID
	incremental bool
	pending     bytes.Buffer
	page        api.EventPage
	started     bool
	ended       bool
	index       uint64
	previous    api.Sequence
	selectedEnd bool
	bytesQueued int
}

func (sink *lbV2LifecycleSink) Write(data []byte) (int, error) {
	if len(data) > api.MaxFrameBytes+1 {
		return 0, lbV2LifecycleIntegrity("event output write exceeded its frame bound")
	}
	_, err := sink.pending.Write(data)
	if err != nil {
		return 0, err
	}
	for {
		decoder := json.NewDecoder(bytes.NewReader(sink.pending.Bytes()))
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				sink.pending.Reset()
				return len(data), nil
			}
			if errors.Is(err, io.ErrUnexpectedEOF) && sink.pending.Len() <= api.MaxFrameBytes {
				return len(data), nil
			}
			return len(data), lbV2LifecycleIntegrity("invalid bounded event stream data")
		}
		sink.pending.Next(int(decoder.InputOffset()))
		if err := sink.lbV2LifecycleValue(raw); err != nil {
			return len(data), err
		}
	}
}

func (sink *lbV2LifecycleSink) lbV2LifecycleEvent(event api.Event) error {
	selection := sink.selection
	if sink.selectedEnd || event.Config != sink.call.Config || event.LifeID != selection.LifeID ||
		event.Run != selection.Run || event.Origin != "service" || event.Seq <= sink.previous {
		return lbV2LifecycleIntegrity("event stream violated its authorized selection")
	}
	sink.previous = event.Seq
	sink.selectedEnd = selection.Until != "" && event.Kind == selection.Until
	return nil
}

func (sink *lbV2LifecycleSink) lbV2LifecycleValue(raw json.RawMessage) error {
	if sink.ended {
		return lbV2LifecycleIntegrity("stream delivered data after its end")
	}
	if !sink.started {
		if err := api.DecodeObject(raw, &sink.page); err != nil ||
			len(sink.page.Events) > 200 || len(sink.page.Cursor) > 4096 {
			return lbV2LifecycleIntegrity("invalid event stream initial snapshot")
		}
		for _, event := range sink.page.Events {
			if err := sink.lbV2LifecycleEvent(event); err != nil {
				return err
			}
		}
		sink.started, sink.bytesQueued = true, len(raw)
		if sink.incremental {
			return json.NewEncoder(sink.call.Stdout).Encode(sink.page)
		}
		return nil
	}
	var frame api.StreamFrame
	if err := api.DecodeObject(raw, &frame); err != nil {
		return lbV2LifecycleIntegrity("invalid event stream frame")
	}
	sink.index++
	if frame.RequestID != sink.requestID || frame.Index != sink.index {
		return lbV2LifecycleIntegrity("event stream request or frame order changed")
	}
	if frame.Error != nil {
		return frame.Error
	}
	if frame.End {
		if frame.Event != nil || frame.Chunk != nil || sink.selection.Until != "" && !sink.selectedEnd {
			return lbV2LifecycleIntegrity("follow ended without its selected committed event")
		}
		sink.ended = true
		sink.page.Cursor, sink.page.Complete = frame.Cursor, true
	} else {
		if frame.Event == nil || frame.Chunk != nil {
			return lbV2LifecycleIntegrity("invalid event stream data frame")
		}
		if err := sink.lbV2LifecycleEvent(*frame.Event); err != nil {
			return err
		}
		if !sink.incremental {
			encoded, err := json.Marshal(frame.Event)
			if err != nil {
				return lbV2LifecycleIntegrity("cannot encode event data")
			}
			sink.bytesQueued += len(encoded)
			if sink.bytesQueued > api.MaxObjectBytes {
				return &api.Error{Code: api.CodeUnavailable, Message: "JSON follow output is full",
					Instead: "Use --format jsonl for incremental output and retained cursors."}
			}
			sink.page.Events = append(sink.page.Events, *frame.Event)
		}
	}
	if sink.incremental {
		return json.NewEncoder(sink.call.Stdout).Encode(frame)
	}
	return nil
}

func lbV2LifecycleStream(ctx context.Context, call Invocation, options *lbV2LifecycleFlags,
	params []byte, selection api.EventTailRequest) error {
	prepared, err := lbV2LifecycleInvocation(call, options)
	if err != nil {
		return err
	}
	if prepared.RequestID == "" {
		prepared.RequestID, err = client.NewRequestID()
		if err != nil {
			return err
		}
	}
	sink := &lbV2LifecycleSink{call: call, selection: selection, requestID: prepared.RequestID,
		incremental: options.lbV2LifecycleGet("format") == "jsonl", previous: selection.Since}
	prepared.Stdout = sink
	// Common invocation owns shared preparation/session setup and the socket.
	// The sink validates actual output incrementally and never mints an end.
	if err := prepared.InvokeRaw(ctx, params); err != nil {
		return err
	}
	if !sink.started || !sink.ended || sink.pending.Len() != 0 {
		return &api.Error{Code: api.CodeUnavailable,
			Message: "event connection ended before its authenticated end frame",
			Instead: "Resume the selected life and run from the retained cursor."}
	}
	if !sink.incremental {
		return json.NewEncoder(call.Stdout).Encode(sink.page)
	}
	return nil
}

func runLaneStart(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.StartRequest, api.Operation](ctx, call)
}

func runLaneAdopt(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.AdoptRequest, api.Operation](ctx, call)
}

func runLaneResume(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.ResumeRequest, api.Operation](ctx, call)
}

func runLaneTurn(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.TurnRequest, api.Operation](ctx, call)
}

func runLaneStop(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.StopRequest, api.Operation](ctx, call)
}

func runLaneMark(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.MarkRequest, api.Operation](ctx, call)
}

func runLaneReview(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.ReviewRequest, api.ReviewReceipt](ctx, call)
}

func runLaneClean(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.CleanRequest, api.Operation](ctx, call)
}

func runLaneArchive(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.ArchiveRequest, api.ArchiveReceipt](ctx, call)
}

func runLaneStatus(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.LifeRef, api.Lane](ctx, call)
}

func runLaneList(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.ListRequest, api.LanePage](ctx, call)
}

func runLaneCheck(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.LifeRef, api.ProcessObservation](ctx, call)
}

func runLaneLoop(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.LoopRequest, api.Operation](ctx, call)
}

func runLaneAttach(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.AttachRequest, api.StreamFrame](ctx, call)
}

func runLaneInput(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.AttachInputRequest, api.Operation](ctx, call)
}

func runEventTail(ctx context.Context, call Invocation) error {
	return lbV2LifecycleRun[api.EventTailRequest, api.EventPage](ctx, call)
}
