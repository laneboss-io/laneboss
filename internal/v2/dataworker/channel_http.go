package dataworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ChannelHTTP is native worker configuration. URL/token come from the one
// selected injected credential, never from a mail body or service environment.
type ChannelHTTP struct {
	Endpoint  api.ID
	URL       string
	Token     string
	Client    *http.Client
	ReceiptID string
}

type ChannelKeep func(context.Context, []byte) (api.BlobRef, error)

type channelAck struct {
	Receipt string     `json:"receipt_id"`
	Digest  api.Digest `json:"payload_sha256"`
}

func ExchangeChannel(ctx context.Context, provider ChannelHTTP, job api.ChannelJob, payload []byte, readOnly bool, keep ChannelKeep, clock api.Clock) (result api.ChannelSendEvidence, err error) {
	if err := api.ValidateChannelJob(job); err != nil {
		return result, err
	}
	if manifest.Hash(payload) != job.Payload.SHA256 || int64(len(payload)) != job.Payload.Bytes || keep == nil || missing(clock) {
		return result, manifest.Invalid("channel exchange lost its exact payload or receipt sink")
	}
	endpoint, err := url.Parse(provider.URL)
	if err != nil || endpoint.Host == "" || endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return result, manifest.Invalid("channel credential has no enrolled HTTP endpoint")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	result = api.ChannelSendEvidence{Schema: "laneboss.channel-result.v2", LeaseID: job.Lease.ID, OperationID: job.Lease.OperationID,
		EffectID: job.Lease.EffectID, MailID: job.MailID, ChannelID: job.ChannelID, ChannelGeneration: job.ChannelGeneration,
		DestinationID: job.DestinationID, ProviderIdempotencyKey: job.ProviderIdempotencyKey, PayloadSHA256: job.Payload.SHA256}
	fail := func(code api.ErrorCode, outcome, message string) (api.ChannelSendEvidence, error) {
		result.Outcome, result.ReadBack = outcome, nil
		result.Error = &api.Error{Code: code, Owner: "lb-v2-messaging", Message: message, Retryable: outcome == "uncertain"}
		return result, nil
	}
	if readOnly && job.Runtime.Reconcile == "unsupported" {
		return fail(api.CodeUnsupported, "unsupported", "enrolled channel cannot reconcile an uncertain send")
	}
	if readOnly && job.Runtime.Reconcile == "receipt_id" && provider.ReceiptID == "" {
		return fail(api.CodePrerequisite, "uncertain", "channel read-back requires the original provider receipt")
	}
	client := provider.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	exchange := func(read bool, receipt string) (channelAck, []byte, error) {
		target := *endpoint
		method := http.MethodPost
		var body io.Reader = bytes.NewReader(payload)
		if read {
			method, body = http.MethodGet, nil
			query := target.Query()
			if job.Runtime.Reconcile == "receipt_id" {
				query.Set("receipt_id", receipt)
			} else {
				query.Set("key", string(job.ProviderIdempotencyKey))
			}
			target.RawQuery = query.Encode()
		}
		request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
		if err != nil {
			return channelAck{}, nil, manifest.Invalid("channel HTTP request could not be constructed")
		}
		if !read {
			// Idempotency-Key otherwise makes a reused HTTP transport replay
			// this POST after a lost acknowledgement. Recovery is read-only.
			request.GetBody = nil
		}
		request.Header.Set("Idempotency-Key", string(job.ProviderIdempotencyKey))
		request.Header.Set("Content-Type", "application/json")
		if provider.Token != "" {
			request.Header.Set("Authorization", "Bearer "+provider.Token)
		}
		response, err := client.Do(request)
		if err != nil {
			return channelAck{}, nil, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-messaging", Message: "channel network outcome is unknown", Retryable: true}
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, api.MaxChunkBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(raw) > api.MaxChunkBytes {
			return channelAck{}, nil, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-messaging", Message: "channel response was incomplete or exceeds its bound", Retryable: true}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return channelAck{}, nil, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-messaging", Message: fmt.Sprintf("channel provider returned HTTP %d", response.StatusCode), Retryable: true}
		}
		var ack channelAck
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&ack) != nil || ack.Receipt == "" || ack.Digest != job.Payload.SHA256 {
			return channelAck{}, nil, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-messaging", Message: "channel acknowledgement does not identify the actual payload"}
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return channelAck{}, nil, manifest.Invalid("channel acknowledgement has trailing data")
		}
		return ack, raw, nil
	}
	exchangeError := func(err error) (api.ChannelSendEvidence, error) {
		var owning *api.Error
		if errors.As(err, &owning) {
			copy := *owning
			result.Outcome, result.ReadBack, result.Error = "uncertain", nil, &copy
			return result, nil
		}
		return result, err
	}
	ack, raw, err := exchange(readOnly, provider.ReceiptID)
	if err != nil {
		return exchangeError(err)
	}
	ref, err := keep(ctx, raw)
	if err != nil {
		return result, err
	}
	if ref.Class != "channel_receipt" || ref.SHA256 != manifest.Hash(raw) || ref.Bytes != int64(len(raw)) {
		return result, manifest.Invalid("channel receipt sink changed the measured bytes")
	}
	result.Response, result.RemoteReceiptID = &ref, ack.Receipt
	if job.Runtime.Reconcile == "unsupported" {
		return fail(api.CodeUnsupported, "unsupported", "enrolled channel cannot read back its acknowledged send")
	}
	read, raw, err := exchange(true, ack.Receipt)
	if err != nil {
		return exchangeError(err)
	}
	if read.Receipt != ack.Receipt || read.Digest != ack.Digest {
		return fail(api.CodeIntegrity, "uncertain", "channel read-back does not confirm the acknowledged payload")
	}
	ref, err = keep(ctx, raw)
	if err != nil {
		return result, err
	}
	if ref.Class != "channel_receipt" || ref.SHA256 != manifest.Hash(raw) || ref.Bytes != int64(len(raw)) {
		return result, manifest.Invalid("channel read-back sink changed the measured bytes")
	}
	result.Outcome = "confirmed"
	result.ReadBack = &api.ChannelReadBack{RemoteReceiptID: read.Receipt, PayloadSHA256: read.Digest, Response: ref,
		ObservedAt: api.Timestamp(clock.Now().UTC().Format(time.RFC3339Nano))}
	return result, api.ValidateChannelSendEvidence(job, result)
}
