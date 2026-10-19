package wire

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/typesafe"
	"laneboss.io/laneboss/internal/v2/api"
)

const MaxResponseBytes = 1 << 20

// FitCheck must run the pinned serving formatter and tokenizer on these exact
// complete bytes. It must honor ctx; a character/byte estimate is not proof.
type FitCheck func(context.Context, []byte) (api.TokenFit, error)

// Retain stores protected exact bytes and returns a checked content reference.
// It must not expose content through ordinary events or copy credential values.
type Retain func(context.Context, string, []byte) (api.BlobRef, error)

// Cost computes actual usage cost using the approved, pinned price source.
type Cost func(inputTokens, outputTokens int64) (int64, error)

// Options are worker-side protected dependencies, never fields accepted by RPC.
// The caller must already hold a durable egress lease. These pure adapters do
// not create that lease; judge.ask stays unavailable until it can be supplied.
type Options struct {
	Endpoint         string
	Config           api.JudgeConfig
	CredentialHandle api.ID
	Credential       api.SecretMaterial `json:"-"`
	Client           *http.Client       `json:"-"`
	Fit              FitCheck           `json:"-"`
	SafetyTokens     int
	Retain           Retain `json:"-"`
	Cost             Cost   `json:"-"`
	ReserveMicros    int64
}

type Adapter struct {
	config        api.JudgeConfig
	endpoint      string
	key           string
	client        *http.Client
	fit           FitCheck
	safety        int
	retain        Retain
	cost          Cost
	reserveMicros int64
}

func (Options) String() string   { return "judge options (credentials redacted)" }
func (Options) GoString() string { return "judge options (credentials redacted)" }
func (Adapter) String() string   { return "judge adapter (credentials redacted)" }
func (Adapter) GoString() string { return "judge adapter (credentials redacted)" }

var _ api.Judge = (*Adapter)(nil)

func New(o Options) (*Adapter, error) {
	resolved, err := api.ResolveJudgeConfig(o.Config)
	if err != nil {
		return nil, err
	}
	o.Config = resolved
	if err := ValidateConfig(o.Config); err != nil {
		return nil, err
	}
	u, err := url.Parse(o.Endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") ||
		(u.Scheme != "http" && u.Scheme != "https") ||
		strings.ContainsAny(o.Endpoint, "\r\n\t ") {
		return nil, failure(api.CodeInvalid, "invalid protected judge endpoint")
	}
	if u.Scheme == "http" {
		if u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
			return nil, failure(api.CodeInvalid, "plaintext judge endpoint must be loopback")
		}
	}
	if o.Config.Provider == "clef-sglang" {
		host := strings.ToLower(strings.TrimRight(u.Hostname(), "."))
		if host == "cloudflare.com" || strings.HasSuffix(host, ".cloudflare.com") {
			return nil, failure(api.CodeInvalid, "hosted Clef endpoints are unsupported")
		}
	}
	key := string(o.Credential.Bytes)
	if key != "" && (len(key) < 16 || len(key) > 8192) {
		return nil, failure(api.CodeInvalid, "invalid judge credential length")
	}
	if strings.IndexFunc(key, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return nil, failure(api.CodeInvalid, "judge credential contains invalid header bytes")
	}
	if key != "" && !ValidID(o.CredentialHandle) || key == "" && o.CredentialHandle != "" {
		return nil, failure(api.CodeInvalid, "judge credential handle and material disagree")
	}
	if o.Config.Provider == "typesafe" && key == "" {
		return nil, failure(api.CodePrerequisite, "TypeSafe credential is unavailable")
	}
	if o.SafetyTokens < 1 || o.SafetyTokens >= o.Config.ContextTokens {
		return nil, failure(api.CodeInvalid, "invalid judge safety token margin")
	}
	if o.ReserveMicros < 1 || o.ReserveMicros > maxInteger {
		return nil, failure(api.CodeInvalid, "invalid judge cost reservation")
	}
	client := http.Client{}
	if o.Client != nil {
		client = *o.Client
	}
	transport, standard := client.Transport.(*http.Transport)
	if standard && transport == nil {
		client.Transport = nil
	}
	if !standard && Nil(client.Transport) {
		client.Transport = nil
	}
	if client.Transport == nil {
		transport = &http.Transport{DialContext: (&net.Dialer{
			Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2: true, MaxIdleConns: 100,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second,
			ExpectContinueTimeout: time.Second}
		standard = true
	}
	if standard {
		transport = transport.Clone()
		transport.Proxy = nil
		transport.DisableCompression = true
		transport.MaxResponseHeaderBytes = MaxResponseBytes
		client.Transport = transport
	}
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Adapter{config: o.Config,
		endpoint: strings.TrimRight(o.Endpoint, "/") + "/v1/systemone",
		key:      key, client: &client, fit: o.Fit, safety: o.SafetyTokens,
		retain: o.Retain, cost: o.Cost, reserveMicros: o.ReserveMicros}, nil
}

func (a *Adapter) prepare(r api.JudgeRequest) ([]byte, []api.ID, error) {
	if r.Config != a.config {
		return nil, nil, failure(api.CodeForbidden, "request cannot select judge configuration")
	}
	body, ids, err := Payload(r)
	if err != nil {
		return nil, nil, err
	}
	if err := screenOutgoing(body, a.key); err != nil {
		return nil, nil, err
	}
	return body, ids, nil
}

// screenOutgoing is the complete serialized request gate used by prepare,
// before retention, fit/byte limits and HTTP. Trusted question text is covered
// by the same gate as named state; it has no separate unscreened path.
func screenOutgoing(body []byte, key string) error {
	if len(body) > MaxScreenInputBytes {
		return failure(api.CodeUnscored, ScreenCapReason)
	}
	decoded, err := typesafe.Decode(body)
	if err != nil {
		return failure(api.CodeIntegrity, "judge serialization is invalid")
	}
	hit, capped := requestScreenResult(decoded, key)
	if capped {
		return failure(api.CodeUnscored, ScreenCapReason)
	}
	if hit {
		return failure(api.CodeUnscored, "credential-shaped input withheld")
	}
	return nil
}

func (a *Adapter) fitBody(ctx context.Context, body []byte) (api.TokenFit, error) {
	fit := api.TokenFit{InputBytes: len(body), ContextTokens: a.config.ContextTokens,
		TokenizerSHA256: a.config.TokenizerSHA256}
	if ctx.Err() != nil {
		fit.Reason = "judge deadline or cancellation before fit"
		return fit, nil
	}
	if len(body) > a.config.MaxBytes || len(body) > api.MaxJudgeBytes {
		fit.Reason = "complete request exceeds byte bound"
		return fit, nil
	}
	if a.fit == nil {
		fit.Reason = "pinned serving tokenizer fit is unavailable"
		return fit, nil
	}
	copyBody := bytes.Clone(body)
	proved, err := a.fit(ctx, copyBody)
	if err != nil || ctx.Err() != nil {
		fit.Reason = "pinned serving tokenizer fit failed or timed out"
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotImplemented {
			return fit, typed
		}
		return fit, nil
	}
	if !bytes.Equal(copyBody, body) || !proved.Proved || proved.InputBytes != len(body) ||
		proved.TokenizerSHA256 != a.config.TokenizerSHA256 ||
		proved.ContextTokens != a.config.ContextTokens || proved.InputTokens < 1 {
		fit.Reason = "complete request token proof is missing or inconsistent"
		return fit, nil
	}
	fit.InputTokens = proved.InputTokens
	if proved.InputTokens >= a.config.ContextTokens-a.safety {
		fit.Reason = "complete formatted request exceeds safe token limit"
		return fit, nil
	}
	fit.Proved = true
	return fit, nil
}

func (a *Adapter) Fit(ctx context.Context, r api.JudgeRequest) (api.TokenFit, error) {
	ctx, cancel := deadline(ctx, r)
	defer cancel()
	body, _, err := a.prepare(r)
	if err != nil {
		return api.TokenFit{Reason: "invalid judge request"}, err
	}
	return a.fitBody(ctx, body)
}

func (a *Adapter) keep(ctx context.Context, class string, raw []byte) (api.BlobRef, error) {
	ref, err := a.retain(ctx, class, bytes.Clone(raw))
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) {
			copy := *typed
			copy.Message = "protected judge byte retention failed"
			copy.Instead = "Repair the named protected object-store dependency."
			return api.BlobRef{}, &copy
		}
		return api.BlobRef{}, failure(api.CodeUnavailable, "protected judge bytes could not be retained")
	}
	if !ValidID(ref.ID) || ref.Class != class || ref.Bytes != int64(len(raw)) ||
		ref.SHA256 != Digest(raw) {
		return api.BlobRef{}, failure(api.CodeIntegrity, "protected judge object receipt disagrees with bytes")
	}
	return ref, nil
}

func (a *Adapter) Evaluate(ctx context.Context, r api.JudgeRequest) (reply api.JudgeReply, err error) {
	started := time.Now()
	reply = api.JudgeReply{ID: r.ID, Status: "unavailable", Results: []api.Judgment{},
		SelectedModel: a.config.Model, DeploymentSHA256: a.config.DeploymentSHA256}
	defer func() { reply.LatencyMS = time.Since(started).Milliseconds() }()
	ctx, cancel := deadline(ctx, r)
	defer cancel()
	body, ids, err := a.prepare(r)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeUnscored {
			reply.UnavailableReason = typed.Message
			return reply, nil
		}
		reply.UnavailableReason = "invalid judge request"
		return reply, err
	}
	for _, id := range ids {
		reply.Results = append(reply.Results, api.Judgment{QuestionID: id,
			Status: "unscored", Reason: "complete judgment is unavailable"})
	}
	unscored := func(reason string) (api.JudgeReply, error) {
		reply.UnavailableReason = reason
		for i := range reply.Results {
			reply.Results[i].Reason = reason
		}
		return reply, nil
	}
	reply.InputBytes = len(body)
	if r.MaxCostMicros == 0 || a.reserveMicros > r.MaxCostMicros {
		return unscored("judge cost budget exhausted")
	}
	if a.retain == nil || a.cost == nil {
		reply.UnavailableReason = "protected byte retention or cost accounting is unavailable"
		return reply, api.NotImplemented("lb-v2-judge", "judge.worker.accounting")
	}
	requestRef, err := a.keep(ctx, "judge_request", body)
	if err != nil {
		reply.UnavailableReason = "exact judge request could not be retained"
		return reply, err
	}
	reply.Request = &requestRef
	fit, err := a.fitBody(ctx, body)
	if err != nil {
		reply.UnavailableReason = fit.Reason
		return reply, err
	}
	reply.InputTokens = fit.InputTokens
	if !fit.Proved {
		return unscored(fit.Reason)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return unscored("judge HTTP request could not be constructed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "laneboss-judge/2")
	if a.key != "" {
		request.Header.Set("Authorization", "Bearer "+a.key)
	}
	response, err := a.client.Do(request)
	if err != nil {
		return unscored(networkReason(ctx, err))
	}
	defer response.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if len(raw) > MaxResponseBytes {
		return unscored("judge response exceeds byte bound")
	}
	if a.key != "" && bytes.Contains(raw, []byte(a.key)) {
		return unscored("judge response withheld")
	}
	root, decodeErr := typesafe.Decode(raw)
	if decodeErr != nil {
		return unscored("judge response is not strict UTF-8 JSON")
	}
	if SensitiveResponse(root, a.key) {
		return unscored("judge response withheld")
	}
	// Preserve screened shape failures, partial and failed HTTP bytes too.
	// Malformed JSON cannot be fully screened, so it has no raw object.
	ref, err := a.keep(ctx, "judge_raw", raw)
	if err != nil {
		reply.UnavailableReason = "exact judge response could not be retained"
		return reply, err
	}
	reply.Raw = &ref
	if readErr != nil {
		return unscored(networkReason(ctx, readErr))
	}
	if response.StatusCode != http.StatusOK {
		return unscored("judge returned unsuccessful HTTP status")
	}
	decoded, decodeErr := decodeResponse(raw, ids, a.config.Model)
	reply.ReportedModel = decoded.model
	if decoded.usageKnown {
		cost, err := a.cost(decoded.input, decoded.output)
		if err != nil || cost < 0 || cost > maxInteger {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code == api.CodeNotImplemented {
				reply.UnavailableReason = "actual judge cost accounting is unavailable"
				return reply, typed
			}
			return unscored("actual judge cost accounting is unavailable")
		}
		reply.CostMicros = cost
		if cost > r.MaxCostMicros || cost > a.reserveMicros {
			return unscored("actual judge cost exceeds its reserved budget")
		}
	}
	if decodeErr != nil {
		return unscored("judge response is malformed, incomplete or reports another model")
	}
	if decoded.partial {
		reply.Status = "partial"
		return unscored("provider reports partial or truncated input or output")
	}
	if decoded.input != int64(fit.InputTokens) {
		return unscored("provider input usage disagrees with complete token proof")
	}
	if ctx.Err() != nil {
		return unscored("judge total deadline or cancellation reached")
	}
	for i, id := range ids {
		p := decoded.answers[id]
		reply.Results[i] = api.Judgment{QuestionID: id, Status: "scored", Probability: &p}
	}
	reply.Status = "scored"
	return reply, nil
}

func networkReason(ctx context.Context, err error) string {
	var timeout net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
		errors.As(err, &timeout) && timeout.Timeout() {
		return "judge total deadline exceeded"
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return "judge request cancelled"
	}
	return "judge transport unavailable"
}
