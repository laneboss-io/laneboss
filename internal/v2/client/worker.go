package client

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// WorkerClient borrows only the credential-pinned installed worker socket. It
// never opens a state file, projects roots or falls back to the public client.
type WorkerClient struct {
	client    *Client
	principal api.WorkerPrincipal
}

func OpenWorker(ctx context.Context, options Options, leaseID api.ID) (*WorkerClient, error) {
	c, err := Open(ctx, options)
	if err != nil {
		return nil, err
	}
	if c.binding == nil || c.binding.Class != api.EndpointWorker || c.binding.WorkerLeaseID != leaseID {
		return nil, errors.Join(wire.Invalid("native worker requires its exact protected lease binding"), c.Close())
	}
	w := &WorkerClient{client: c}
	if err := w.call(ctx, api.WorkerPrincipalRead, api.WorkerInputRequest{LeaseID: leaseID}, &w.principal); err != nil {
		return nil, errors.Join(err, c.Close())
	}
	p := w.principal
	if !sameWorkerBinding(*c.binding, p.Endpoint) || p.Lease.ID != leaseID || api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerPrincipalRead, time.Now()) != nil {
		return nil, errors.Join(wire.Invalid("native worker principal differs from its installed connection"), c.Close())
	}
	return w, nil
}

func sameWorkerBinding(a, b api.InstalledBinding) bool {
	left, le := json.Marshal(a)
	right, re := json.Marshal(b)
	return le == nil && re == nil && string(left) == string(right)
}

func (w *WorkerClient) Principal() api.WorkerPrincipal {
	// Do not share mutable plan argv/grants/claim slices with a job consumer.
	raw, err := json.Marshal(w.principal)
	if err != nil {
		return api.WorkerPrincipal{}
	}
	var p api.WorkerPrincipal
	if api.DecodeObject(raw, &p) != nil {
		return api.WorkerPrincipal{}
	}
	return p
}
func (w *WorkerClient) Close() error { return w.client.Close() }

func (w *WorkerClient) call(ctx context.Context, operation api.WorkerOperation, input, output any) (resultErr error) {
	c := w.client
	c.callMu.Lock()
	defer c.callMu.Unlock()
	if c.binding == nil || c.binding.Class != api.EndpointWorker {
		return wire.Invalid("private worker call requires its native installed binding")
	}
	params, err := json.Marshal(input)
	if err != nil {
		return err
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	key, err := wire.NewID()
	if err != nil {
		return err
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: c.Options.Config, Method: api.Method(operation), RequestID: id, IdempotencyKey: key, Params: params}
	request.RequestSHA256, err = api.RequestDigest(request)
	if err != nil {
		return err
	}
	c.mu.Lock()
	closed, connection := c.closed, c.primary
	c.mu.Unlock()
	if closed || connection == nil {
		return transportError(errors.New("worker connection is closed"))
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	deadline := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return transportError(err)
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := wire.WriteFrame(connection, raw); err != nil {
		return transportError(err)
	}
	raw, err = wire.ReadFrame(connection)
	if err != nil {
		return transportError(err)
	}
	var response api.Response
	if err := api.DecodeObject(raw, &response); err != nil {
		return err
	}
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != id || (response.Error == nil) == (len(response.Result) == 0) {
		return wire.Invalid("private worker reply changed its request or result envelope")
	}
	if response.Error != nil {
		return response.Error
	}
	return api.DecodeObject(response.Result, output)
}

func (w *WorkerClient) scope(scope api.Scope) error {
	p := w.principal
	if scope.Config != p.Endpoint.Config || scope.Actor != p.Record.Actor || scope.LaunchID != p.Record.ID || scope.EndpointGeneration != p.Record.EndpointGeneration || scope.Request.Method != "" {
		return wire.Invalid("worker job cannot borrow another scope")
	}
	return nil
}
func (w *WorkerClient) WorkerInput(ctx context.Context, scope api.Scope, input api.WorkerInputRequest) (result api.WorkerJobInput, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerInputRead, input, &result)
	return
}
func (w *WorkerClient) WorkerResult(ctx context.Context, scope api.Scope, input api.WorkerResultSubmission) (result api.WorkerResultReceipt, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerResultAppend, input, &result)
	return
}
func (w *WorkerClient) Read(ctx context.Context, input api.BlobReadRequest) (result api.BlobChunk, err error) {
	err = w.call(ctx, api.WorkerObjectRead, input, &result)
	return
}
func (w *WorkerClient) ArchivePart(ctx context.Context, scope api.Scope, leaseID api.ID, index uint64, data []byte) (result api.BlobRef, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerArchivePart, archivejob.PartRequest{LeaseID: leaseID, Index: index, Bytes: data}, &result)
	return
}

func (w *WorkerClient) ChannelContext(ctx context.Context, scope api.Scope, request api.WorkerInputRequest) (result api.ChannelContext, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerChannelContext, request, &result)
	return
}

func (w *WorkerClient) ChannelReceipt(ctx context.Context, scope api.Scope, request api.ChannelReceiptRequest) (result api.BlobRef, err error) {
	if err = w.scope(scope); err != nil {
		return result, err
	}
	err = w.call(ctx, api.WorkerChannelReceipt, request, &result)
	return
}
