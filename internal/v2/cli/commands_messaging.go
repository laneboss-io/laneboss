package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/messaging"
)

func init() {
	for _, entry := range []struct {
		method api.Method
		check  func(json.RawMessage) error
	}{
		{"mail.send", func(raw json.RawMessage) error { _, err := messaging.DecodeMailSend(raw); return err }},
		{"mail.list", func(raw json.RawMessage) error { _, err := messaging.DecodeMailList(raw); return err }},
		{"report.submit", func(raw json.RawMessage) error { _, err := messaging.DecodeReport(raw); return err }},
	} {
		if err := RegisterInputValidator(entry.method, "lb-v2-messaging", entry.check); err != nil {
			panic(err) // A broken registration must stop CLI initialization.
		}
	}
}

// runMailSend maps file/flag inputs to api.MailSendRequest, then calls mail.send.
func runMailSend(ctx context.Context, call Invocation) error {
	options, err := lbV2MessagingParse(call, "mail.send")
	if err != nil {
		return err
	}
	var request api.MailSendRequest
	if options.request != "" {
		raw, err := lbV2MessagingReadFile(options.request, call.Stdin, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		request, err = messaging.DecodeMailSend(raw)
		if err != nil {
			return err
		}
	} else {
		ref, err := lbV2MessagingContent(ctx, call, options)
		if err != nil {
			return err
		}
		request = api.MailSendRequest{
			RecipientLifeID: api.ID(options.life), ChannelGrantID: api.ID(options.channel),
			Content: ref, Ask: options.ask, ReplyTo: api.ID(options.reply),
		}
	}
	var result api.Mail
	if err := lbV2MessagingInvoke(ctx, call, "mail.send", options.key, request, &result); err != nil {
		return err
	}
	if result.ID == "" || result.QueuedSeq == 0 || result.Status != "queued" || result.Content != request.Content || result.RecipientLifeID != request.RecipientLifeID || result.ChannelGrantID != request.ChannelGrantID || result.Ask != request.Ask || result.ReplyTo != request.ReplyTo {
		return lbV2MessagingError(api.CodeIntegrity, "service returned an invalid mail enqueue receipt")
	}
	return json.NewEncoder(call.Stdout).Encode(result)
}

// runMailList maps file/flag inputs to api.ListRequest, then calls mail.list.
func runMailList(ctx context.Context, call Invocation) error {
	options, err := lbV2MessagingParse(call, "mail.list")
	if err != nil {
		return err
	}
	request := api.ListRequest{LifeID: api.ID(options.life), Cursor: options.cursor, Limit: options.limit}
	if options.request != "" {
		raw, err := lbV2MessagingReadFile(options.request, call.Stdin, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		request, err = messaging.DecodeMailList(raw)
		if err != nil {
			return err
		}
	}
	var result api.MailPage
	if err := lbV2MessagingInvoke(ctx, call, "mail.list", options.key, request, &result); err != nil {
		return err
	}
	if result.Messages == nil || len(result.Messages) > request.Limit {
		return lbV2MessagingError(api.CodeIntegrity, "service returned an invalid mailbox page")
	}
	return json.NewEncoder(call.Stdout).Encode(result)
}

// runReportSubmit maps file/flag inputs to api.ReportRequest, then calls report.submit.
func runReportSubmit(ctx context.Context, call Invocation) error {
	options, err := lbV2MessagingParse(call, "report.submit")
	if err != nil {
		return err
	}
	var request api.ReportRequest
	if options.request != "" {
		raw, err := lbV2MessagingReadFile(options.request, call.Stdin, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		request, err = messaging.DecodeReport(raw)
		if err != nil {
			return err
		}
	} else {
		ref, err := lbV2MessagingContent(ctx, call, options)
		if err != nil {
			return err
		}
		request = api.ReportRequest{Content: ref, Ask: options.ask, Artifacts: []api.BlobRef{}, ChannelGrantID: api.ID(options.channel), ReplyTo: api.ID(options.reply)}
	}
	var result api.Mail
	if err := lbV2MessagingInvoke(ctx, call, "report.submit", options.key, request, &result); err != nil {
		return err
	}
	if result.ID == "" || result.QueuedSeq == 0 || result.Status != "queued" || result.Content != request.Content || result.ChannelGrantID != request.ChannelGrantID || result.ReplyTo != request.ReplyTo || result.Ask != request.Ask || !reflect.DeepEqual(result.Artifacts, request.Artifacts) {
		return lbV2MessagingError(api.CodeIntegrity, "service returned an invalid report enqueue receipt")
	}
	return json.NewEncoder(call.Stdout).Encode(result)
}

// The shared CLI package reserves runMailSend/runMailList/runReportSubmit in
// dispatch.go. Every additional package-level declaration uses this lane's
// prefix so independently landed feature files cannot collide with it.
type lbV2MessagingOptions struct {
	request, file, life, channel, reply, cursor string
	contentRef                                  string
	key                                         api.ID
	ask                                         bool
	limit                                       int
}

func lbV2MessagingError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message, Owner: "lb-v2-messaging", Instead: "Use --request FILE for the exact frozen request body, or explicit file and immutable life/grant flags."}
}

func lbV2MessagingIDValid(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func lbV2MessagingParse(call Invocation, method api.Method) (lbV2MessagingOptions, error) {
	args := call.Args
	options := lbV2MessagingOptions{limit: 50, key: call.IdempotencyKey}
	seen := make(map[string]bool)
	ergonomic := false
	for i := 0; i < len(args); i++ {
		key, value, supplied := strings.Cut(args[i], "=")
		if key == "--lane" || key == "--recipient-life-id" {
			key = "--life-id"
		}
		if seen[key] {
			return options, lbV2MessagingError(api.CodeInvalid, "duplicate messaging flag")
		}
		seen[key] = true
		if key == "--ask" {
			if supplied || method == "mail.list" {
				return options, lbV2MessagingError(api.CodeInvalid, "--ask is a send/report boolean flag")
			}
			options.ask, ergonomic = true, true
			continue
		}
		switch key {
		case "--request", "--idempotency-key", "--format":
		case "--file", "--content-ref", "--channel-grant-id", "--reply-to":
			if method == "mail.list" {
				return options, lbV2MessagingError(api.CodeInvalid, "mail list does not accept send flags")
			}
			ergonomic = true
		case "--life-id":
			if method == "report.submit" {
				return options, lbV2MessagingError(api.CodeInvalid, "report recipient is derived from the authentic starter")
			}
			ergonomic = true
		case "--cursor", "--limit":
			if method != "mail.list" {
				return options, lbV2MessagingError(api.CodeInvalid, "pagination flags apply to mail list")
			}
			ergonomic = true
		default:
			return options, lbV2MessagingError(api.CodeInvalid, "unknown messaging flag or positional argument")
		}
		if !supplied {
			i++
			if i == len(args) {
				return options, lbV2MessagingError(api.CodeInvalid, "messaging flag is missing its value")
			}
			value = args[i]
		}
		if value == "" && key != "--cursor" || strings.HasPrefix(value, "--") {
			return options, lbV2MessagingError(api.CodeInvalid, "messaging flag has an invalid or missing value")
		}
		switch key {
		case "--request":
			options.request = value
		case "--file":
			options.file = value
		case "--content-ref":
			options.contentRef = value
		case "--life-id":
			options.life = value
		case "--channel-grant-id":
			options.channel = value
		case "--reply-to":
			options.reply = value
		case "--cursor":
			options.cursor = value
		case "--limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > 200 {
				return options, lbV2MessagingError(api.CodeInvalid, "mail list limit must be from 1 to 200")
			}
			options.limit = limit
		case "--idempotency-key":
			if options.key != "" {
				return options, lbV2MessagingError(api.CodeInvalid, "duplicate retained idempotency key")
			}
			if !lbV2MessagingIDValid(value) || len(value) < 22 {
				return options, lbV2MessagingError(api.CodeInvalid, "idempotency key must be a random ID with at least 128 bits")
			}
			options.key = api.ID(value)
		case "--format":
			if value != "json" {
				return options, lbV2MessagingError(api.CodeInvalid, "messaging output format is json")
			}
		}
	}
	if options.request != "" && ergonomic {
		return options, lbV2MessagingError(api.CodeInvalid, "--request cannot be combined with body flags")
	}
	if options.file != "" && options.contentRef != "" {
		return options, lbV2MessagingError(api.CodeInvalid, "--file and --content-ref are exclusive")
	}
	if options.request == "" && method != "mail.list" && options.file == "" && options.contentRef == "" {
		return options, lbV2MessagingError(api.CodeInvalid, "messaging requires --request, --file or --content-ref FILE")
	}
	if options.file != "" && call.ProofFile != "" {
		return options, lbV2MessagingError(api.CodeInvalid, "a confirmed message requires --content-ref or --request; upload before confirmation")
	}
	if options.request == "" && method == "mail.send" && (options.life == "") == (options.channel == "") {
		return options, lbV2MessagingError(api.CodeInvalid, "mail send requires exactly one immutable life or channel grant")
	}
	for _, id := range []string{options.life, options.channel, options.reply} {
		if id != "" && !lbV2MessagingIDValid(id) {
			return options, lbV2MessagingError(api.CodeInvalid, "messaging life, grant and reply identifiers are invalid")
		}
	}
	if len(options.cursor) > 4096 {
		return options, lbV2MessagingError(api.CodeInvalid, "mail list cursor exceeds the bound")
	}
	if options.key == "" {
		if api.Methods[method].Mutation {
			return options, lbV2MessagingError(api.CodeInvalid, "messaging mutation requires --idempotency-key ID retained for retries")
		}
		key, err := lbV2MessagingNewID()
		if err != nil {
			return options, err
		}
		options.key = key
	}
	if !lbV2MessagingIDValid(string(options.key)) || len(options.key) < 22 {
		return options, lbV2MessagingError(api.CodeInvalid, "idempotency key must be a random ID with at least 128 bits")
	}
	return options, nil
}

func lbV2MessagingContent(ctx context.Context, call Invocation, options lbV2MessagingOptions) (api.BlobRef, error) {
	if options.contentRef != "" {
		raw, err := lbV2MessagingReadFile(options.contentRef, call.Stdin, api.MaxFrameBytes)
		if err != nil {
			return api.BlobRef{}, err
		}
		ref, err := messaging.DecodeMailBlobResult(raw)
		if err != nil {
			return api.BlobRef{}, lbV2MessagingError(api.CodeInvalid, "content reference must be an exact committed report blob")
		}
		return ref, nil
	}
	data, err := lbV2MessagingReadFile(options.file, call.Stdin, messaging.MaxMailBytes)
	if err != nil {
		return api.BlobRef{}, err
	}
	if err := messaging.CheckContent(data); err != nil {
		return api.BlobRef{}, err
	}
	return lbV2MessagingUpload(ctx, call, options.key, data)
}

func lbV2MessagingNewID() (api.ID, error) {
	return client.NewRequestID()
}

func lbV2MessagingReadFile(path string, stdin io.Reader, maximum int64) ([]byte, error) {
	var data []byte
	var err error
	if path == "-" {
		if stdin == nil {
			return nil, lbV2MessagingError(api.CodeInvalid, "messaging standard input is closed")
		}
		data, err = io.ReadAll(io.LimitReader(stdin, maximum+1))
	} else {
		file, openErr := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return nil, lbV2MessagingError(api.CodeInvalid, "cannot read the messaging input file")
		}
		data, err = func() ([]byte, error) {
			info, err := file.Stat()
			if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
				return nil, lbV2MessagingError(api.CodeInvalid, "messaging input must be a bounded regular file")
			}
			return io.ReadAll(io.LimitReader(file, maximum+1))
		}()
		closeErr := file.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}
	if err != nil || int64(len(data)) > maximum {
		return nil, lbV2MessagingError(api.CodeInvalid, "messaging input could not be read within its byte bound")
	}
	return data, nil
}

func lbV2MessagingSubkey(key api.ID, phase string) api.ID {
	digest := sha256.Sum256([]byte(string(key) + "\x00" + phase))
	return api.ID(hex.EncodeToString(digest[:]))
}

func lbV2MessagingUpload(ctx context.Context, call Invocation, key api.ID, data []byte) (api.BlobRef, error) {
	call.RequestID = "" // Upload correlations are distinct from the final RPC.
	digest := sha256.Sum256(data)
	want := api.BlobRef{Class: "report", Bytes: int64(len(data)), SHA256: api.Digest(hex.EncodeToString(digest[:]))}
	var upload api.BlobUpload
	if err := lbV2MessagingInvoke(ctx, call, "blob.begin", lbV2MessagingSubkey(key, "begin"), api.BlobBeginRequest{Class: want.Class, Bytes: want.Bytes, SHA256: want.SHA256}, &upload); err != nil {
		return api.BlobRef{}, err
	}
	if !lbV2MessagingIDValid(string(upload.ObjectID)) || upload.MaxChunkBytes < 1 || upload.MaxChunkBytes > api.MaxChunkBytes {
		return api.BlobRef{}, lbV2MessagingError(api.CodeIntegrity, "service returned an invalid blob upload")
	}
	want.ID = upload.ObjectID
	for offset := 0; offset < len(data); {
		end := offset + upload.MaxChunkBytes
		if end > len(data) {
			end = len(data)
		}
		part := data[offset:end]
		hash := sha256.Sum256(part)
		chunk := api.BlobChunk{ObjectID: upload.ObjectID, Offset: int64(offset), Data: part, SHA256: api.Digest(hex.EncodeToString(hash[:]))}
		var acknowledgement api.BlobUpload
		phase := fmt.Sprintf("chunk-%d", offset)
		if err := lbV2MessagingInvoke(ctx, call, "blob.chunk", lbV2MessagingSubkey(key, phase), chunk, &acknowledgement); err != nil {
			return api.BlobRef{}, err
		}
		if acknowledgement.ObjectID != upload.ObjectID || acknowledgement.MaxChunkBytes != upload.MaxChunkBytes {
			return api.BlobRef{}, lbV2MessagingError(api.CodeIntegrity, "service changed the blob upload identity or chunk bound")
		}
		offset = end
	}
	var committed api.BlobRef
	if err := lbV2MessagingInvoke(ctx, call, "blob.commit", lbV2MessagingSubkey(key, "commit"), api.BlobCommitRequest{ObjectID: upload.ObjectID, SHA256: want.SHA256}, &committed); err != nil {
		return api.BlobRef{}, err
	}
	if committed != want {
		return api.BlobRef{}, lbV2MessagingError(api.CodeIntegrity, "committed blob differs from the exact input bytes")
	}
	return committed, nil
}

// All subcalls borrow Invocation's shared socket, request preparation and proof
// flow. Buffer the result until the feature's semantic decoder accepts it.
func lbV2MessagingInvoke(ctx context.Context, call Invocation, method api.Method, key api.ID, params, target any) error {
	var output bytes.Buffer
	call.Method, call.IdempotencyKey, call.Stdout = method, key, &output
	if err := call.Invoke(ctx, params); err != nil {
		return err
	}
	return lbV2MessagingDecodeResult(output.Bytes(), target)
}

func lbV2MessagingDecodeResult(raw json.RawMessage, target any) error {
	switch result := target.(type) {
	case *api.Mail:
		value, err := messaging.DecodeMailResult(raw)
		if err != nil {
			return err
		}
		*result = value
	case *api.MailPage:
		value, err := messaging.DecodeMailPageResult(raw)
		if err != nil {
			return err
		}
		*result = value
	case *api.BlobUpload:
		value, err := messaging.DecodeMailUploadResult(raw)
		if err != nil {
			return err
		}
		*result = value
	case *api.BlobRef:
		value, err := messaging.DecodeMailBlobResult(raw)
		if err != nil {
			return err
		}
		*result = value
	default:
		return lbV2MessagingError(api.CodeIntegrity, "messaging selected an unknown result type")
	}
	return nil
}
