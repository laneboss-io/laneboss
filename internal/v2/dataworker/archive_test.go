package dataworker

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// A byte-backed protocol fixture only. It is not a native peer, helper freeze,
// durable database, authenticated service or installed worker acceptance test.
type archivePorts struct {
	input       api.WorkerJobInput
	objects     map[api.ID][]byte
	parts       []api.BlobRef
	result      []byte
	reads       int64
	mode        string
	submissions int
}

func (p *archivePorts) WorkerInput(_ context.Context, _ api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if request.LeaseID != p.input.LeaseID {
		return api.WorkerJobInput{}, errors.New("foreign fixture lease")
	}
	return p.input, nil
}

func (p *archivePorts) WorkerResult(_ context.Context, _ api.Scope, request api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	if request.LeaseID != p.input.LeaseID || request.InputSHA256 != p.input.Input.SHA256 || request.ExpectedGeneration != 1 {
		return api.WorkerResultReceipt{}, errors.New("foreign fixture submission")
	}
	p.submissions++
	p.result = append([]byte{}, request.Result...)
	ref := api.BlobRef{ID: "result", Class: "worker_result", Bytes: int64(len(request.Result)), SHA256: manifest.Hash(request.Result)}
	p.objects[ref.ID] = append([]byte{}, request.Result...)
	return api.WorkerResultReceipt{LeaseID: p.input.LeaseID, StageID: p.input.StageID, Generation: 2, CommittedSeq: 19, Result: ref}, nil
}

func (p *archivePorts) ArchivePart(_ context.Context, _ api.Scope, lease api.ID, index uint64, data []byte) (api.BlobRef, error) {
	if lease != p.input.LeaseID || index != uint64(len(p.parts)) || len(data) == 0 || len(data) > api.MaxChunkBytes {
		return api.BlobRef{}, errors.New("foreign or unordered fixture append")
	}
	if p.mode == "sink" {
		return api.BlobRef{}, errors.New("fixture durable sink failure")
	}
	ref := api.BlobRef{ID: api.ID(fmt.Sprintf("part-%d", index)), Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	p.objects[ref.ID] = append([]byte{}, data...)
	if p.mode == "stored" {
		p.objects[ref.ID][0] ^= 1
	}
	p.parts = append(p.parts, ref)
	if p.mode == "ack" {
		ref.SHA256 = manifest.Hash([]byte("wrong acknowledgement"))
	}
	return ref, nil
}

func (p *archivePorts) read(_ context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
	data, found := p.objects[request.ObjectID]
	if !found || request.Offset < 0 || request.Offset > int64(len(data)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, errors.New("foreign fixture object range")
	}
	part := append([]byte{}, data[request.Offset:min(int64(len(data)), request.Offset+int64(request.Limit))]...)
	if strings.HasPrefix(string(request.ObjectID), "part-") {
		p.reads += int64(len(part))
	}
	return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: part, SHA256: manifest.Hash(part)}, nil
}

func archiveFixture(t *testing.T, mode string) (ArchiveJob, *archivePorts) {
	t.Helper()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	expires := api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))
	ports := &archivePorts{objects: map[api.ID][]byte{}, mode: mode}
	put := func(id api.ID, class string, value any) api.BlobRef {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		ports.objects[id] = append([]byte{}, raw...)
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
	}
	data := bytes.Repeat([]byte("actual archive content\n"), 30000)
	content := api.BlobRef{ID: "content", Class: "artifact", Bytes: int64(len(data)), SHA256: manifest.Hash(data)}
	ports.objects[content.ID] = data
	snapshot := put("snapshot", "manifest", api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "work/file", Kind: "file", Mode: 0600, Content: &content}}})
	target := api.LifeRef{LifeID: "life", Run: 2}
	if mode == "target" {
		target.Run = 0
	}
	zero := uint64(0)
	freeze := archivejob.Freeze{Target: target, LaunchID: "agent-launch", CancellationEpoch: 3, Snapshot: snapshot,
		Writers: &zero, WritableExports: &zero, ObservedAt: api.Timestamp(now.Format(time.RFC3339Nano))}
	switch mode {
	case "writers":
		one := uint64(1)
		freeze.Writers = &one
	case "unknown":
		freeze.WritableExports = nil
	case "freeze":
		freeze.Target.Run++
	}
	frozen := put("freeze", "manifest", freeze)
	budget := api.Budget{WallMS: 60000, CPUSeconds: 60, MemoryBytes: 8 << 20, DiskBytes: 4 << 20, Processes: 2, Currency: "USD"}
	intent := archivejob.Intent{Request: api.ArchiveRequest{Target: target, ExpectedGeneration: 5}, OperationID: "operation", CancellationEpoch: 3, EndEventID: "end-event", EndSeq: 9}
	input := archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: "archive-job", Intent: intent, Freeze: frozen, ReceiptID: "archive-receipt", StoreID: "archive-store", Budget: budget}
	ref := put("input", "archive_input", input)
	lease := api.WorkerLease{ID: "archive-lease", Kind: "archive", Target: target, OperationID: intent.OperationID, EffectID: "effect", Input: ref,
		RuntimeManifest: snapshot, GrantSetID: "archive-grants", Generation: 1, ExpiresAt: expires, ConsumedBy: "worker-launch"}
	record := api.LaunchRecord{Kind: "worker", ID: lease.ConsumedBy, Config: "example", Target: target, Actor: api.Actor{Kind: "worker", ID: "worker-principal"},
		HostUID: 22002, ContainmentID: "worker-containment", ProcessGeneration: "worker-leader", GrantSetID: lease.GrantSetID, EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Class: api.EndpointWorker, Config: record.Config, Target: &target, WorkerLeaseID: lease.ID, LaunchID: record.ID, EndpointGeneration: 1}
	cause := &api.InternalIntent{ID: "intent", Kind: api.InternalLifecycleEffect, Config: record.Config, Target: target,
		Actor: api.Actor{Kind: "service", ID: "outbox"}, RequestedBy: api.Actor{Kind: "human", ID: "requester"}, CauseOperationID: intent.OperationID,
		CauseRequestID: "request", EffectID: lease.EffectID, CancellationEpoch: intent.CancellationEpoch}
	plan := &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "archive", Input: ref, GrantSetID: lease.GrantSetID, Budget: budget}
	claim := api.EffectLease{ClaimID: "claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 2, ClaimID: "claim", ClaimantID: "outbox", ClaimExpiresAt: expires,
		Effect: api.Effect{ID: lease.EffectID, OperationID: intent.OperationID, Context: cause, Worker: plan}}}
	principal := api.WorkerPrincipal{StageID: input.JobID, Lease: lease, Record: record, Endpoint: endpoint, BootID: "boot", AllocationGeneration: 1,
		CancellationEpoch: intent.CancellationEpoch, Claim: claim, Peer: api.PeerFacts{HostUID: record.HostUID, HostGID: 22002, HostPID: 100, ProcessGeneration: "worker-connector", ContainmentID: record.ContainmentID}}
	ports.input = api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: input.JobID, LeaseID: lease.ID, Kind: lease.Kind, OperationID: lease.OperationID,
		EffectID: lease.EffectID, Input: ref, Bytes: append([]byte{}, ports.objects[ref.ID]...)}
	job := ArchiveJob{Principal: principal, Scope: api.Scope{Config: record.Config, Actor: record.Actor, LaunchID: record.ID, EndpointGeneration: 1}, Bootstrap: ports, Sink: ports, Read: ports.read, Clock: workerClock{now}}
	if mode == "identity" {
		job.Scope.Actor = cause.RequestedBy
	}
	if mode == "expired" {
		job.Clock = workerClock{now.Add(2 * time.Minute)}
	}
	if mode == "source" {
		ports.objects[content.ID][0] ^= 1
	}
	return job, ports
}

func TestArchiveWorker(t *testing.T) {
	job, ports := archiveFixture(t, "valid")
	receipt, err := RunInternalJob(context.Background(), "example", []string{"--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Principal.Lease.ID)}, job)
	if err != nil || receipt.Result.Class != "worker_result" || ports.submissions != 1 {
		t.Fatalf("archive did not submit its actual measured result: %v", err)
	}
	var result archivejob.Completion
	if err := api.DecodeObject(ports.result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Receipt.ArchiveSHA256 != result.Receipt.ReadBackSHA256 || result.Receipt.ArchiveSHA256 == job.Principal.Lease.Input.SHA256 ||
		ports.reads != result.Archive.Bytes || len(result.Archive.Parts) < 2 || result.Receipt.ID != "archive-receipt" {
		t.Fatal("archive result omitted actual committed multipart read-back")
	}
}

func TestArchiveWorkerRefuses(t *testing.T) {
	for _, mode := range []string{"target", "writers", "unknown", "freeze", "identity", "expired", "source", "sink", "ack", "stored"} {
		t.Run(mode, func(t *testing.T) {
			job, ports := archiveFixture(t, mode)
			if _, err := RunArchive(context.Background(), job); err == nil || ports.submissions != 0 || len(ports.result) != 0 {
				t.Fatal("archive submitted a receipt after an authority, freeze, source or read-back failure")
			}
		})
	}
}

func TestArchiveFrozenInput(t *testing.T) {
	var digests []api.Digest
	for _, variant := range []byte{'a', 'b'} {
		t.Run(string(variant), func(t *testing.T) {
			job, ports := archiveFixture(t, "valid")
			put := func(id api.ID, class string, raw []byte) api.BlobRef {
				ports.objects[id] = append([]byte{}, raw...)
				return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: manifest.Hash(raw)}
			}
			encode := func(value any) []byte {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return raw
			}
			// Leave the old source/freeze/input objects readable. The producer
			// must follow this exact newly leased chain, not an ambient source.
			content := bytes.Repeat([]byte{variant}, len(ports.objects["content"]))
			ref := put(api.ID("content-"+string(variant)), "artifact", content)
			tree := api.ObjectManifest{Schema: "laneboss.objects.v2", Entries: []api.ObjectEntry{{Path: "work/file", Kind: "file", Mode: 0600, Content: &ref}}}
			snapshot := put(api.ID("snapshot-"+string(variant)), "manifest", encode(tree))
			var input archivejob.Input
			if err := api.DecodeObject(ports.input.Bytes, &input); err != nil {
				t.Fatal(err)
			}
			var freeze archivejob.Freeze
			if err := api.DecodeObject(ports.objects[input.Freeze.ID], &freeze); err != nil {
				t.Fatal(err)
			}
			freeze.Snapshot = snapshot
			input.Freeze = put(api.ID("freeze-"+string(variant)), "manifest", encode(freeze))
			raw := encode(input)
			inputRef := put(api.ID("input-"+string(variant)), "archive_input", raw)
			job.Principal.Lease.Input = inputRef
			job.Principal.Claim.Record.Effect.Worker.Input = inputRef
			ports.input.Input, ports.input.Bytes = inputRef, raw
			if _, err := RunArchive(context.Background(), job); err != nil {
				t.Fatal(err)
			}
			var result archivejob.Completion
			if err := api.DecodeObject(ports.result, &result); err != nil {
				t.Fatal(err)
			}
			var stored bytes.Buffer
			for _, part := range result.Archive.Parts {
				actual := ports.objects[part.ID]
				if int64(len(actual)) != part.Bytes || manifest.Hash(actual) != part.SHA256 {
					t.Fatal("frozen-input witness lost an actual persisted part")
				}
				if _, err := stored.Write(actual); err != nil {
					t.Fatal(err)
				}
			}
			wantManifest, err := api.CanonicalJSON(ports.objects[snapshot.ID])
			if err != nil {
				t.Fatal(err)
			}
			seenManifest, seenFile := 0, 0
			tr := tar.NewReader(bytes.NewReader(stored.Bytes()))
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				data, err := io.ReadAll(tr)
				if err != nil {
					t.Fatal(err)
				}
				switch h.Name {
				case "manifest.json":
					if !bytes.Equal(data, wantManifest) {
						t.Fatal("archive was built from a different frozen manifest")
					}
					seenManifest++
				case "data/work/file":
					if !bytes.Equal(data, content) {
						t.Fatal("archive was built from different frozen file bytes")
					}
					seenFile++
				default:
					t.Fatal("frozen-input witness contains an unexpected member")
				}
			}
			if seenManifest != 1 || seenFile != 1 || result.Receipt.Manifest != snapshot ||
				manifest.Hash(stored.Bytes()) != result.Receipt.ArchiveSHA256 || result.Receipt.ReadBackSHA256 != result.Receipt.ArchiveSHA256 {
				t.Fatal("archive receipt did not bind its exact frozen input and actual tar bytes")
			}
			digests = append(digests, result.Receipt.ArchiveSHA256)
		})
	}
	if len(digests) != 2 || digests[0] == digests[1] {
		t.Fatal("distinct frozen inputs did not produce distinct measured archives")
	}
}

type archiveSinkFunc func(context.Context, api.Scope, api.ID, uint64, []byte) (api.BlobRef, error)

func (sink archiveSinkFunc) ArchivePart(ctx context.Context, scope api.Scope, lease api.ID, index uint64, data []byte) (api.BlobRef, error) {
	return sink(ctx, scope, lease, index, data)
}

func TestArchiveStoredCopy(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name := "valid"
		if corrupt {
			name = "stored-change"
		}
		t.Run(name, func(t *testing.T) {
			job, ports := archiveFixture(t, "valid")
			producer := map[api.ID][]byte{}
			seen, eof := map[api.ID]int64{}, map[api.ID]bool{}
			changedRead := false
			job.Sink = archiveSinkFunc(func(ctx context.Context, scope api.Scope, lease api.ID, index uint64, data []byte) (api.BlobRef, error) {
				ref, err := ports.ArchivePart(ctx, scope, lease, index, data)
				if err != nil {
					return ref, err
				}
				producer[ref.ID] = append([]byte{}, data...)
				if corrupt {
					ports.objects[ref.ID][0] ^= 1
				}
				return ref, nil
			})
			job.Read = func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
				chunk, err := ports.read(ctx, request)
				if original, found := producer[request.ObjectID]; found && err == nil {
					end := chunk.Offset + int64(len(chunk.Data))
					if !bytes.Equal(chunk.Data, ports.objects[request.ObjectID][chunk.Offset:end]) {
						t.Fatal("worker reader did not return its actual persisted range")
					}
					seen[request.ObjectID] += int64(len(chunk.Data))
					eof[request.ObjectID] = eof[request.ObjectID] || len(chunk.Data) == 0 && end == int64(len(original))
					changedRead = changedRead || !bytes.Equal(chunk.Data, original[chunk.Offset:end])
				}
				return chunk, err
			}
			_, err := RunArchive(context.Background(), job)
			if len(producer) == 0 {
				t.Fatal("independent-read witness never reached the real archive producer")
			}
			for _, ref := range ports.parts {
				if manifest.Hash(producer[ref.ID]) != ref.SHA256 || len(producer[ref.ID]) != int(ref.Bytes) {
					t.Fatal("stored-copy fault changed the producer's acknowledged bytes")
				}
				if !corrupt && (seen[ref.ID] != ref.Bytes || !eof[ref.ID]) {
					t.Fatal("worker did not independently read each persisted part and EOF")
				}
			}
			if corrupt {
				if err == nil || !changedRead || ports.submissions != 0 {
					t.Fatal("worker trusted producer memory instead of independently reading changed storage")
				}
			} else if err != nil || ports.submissions != 1 || changedRead {
				t.Fatalf("worker refused an unchanged independently read stored copy: %v", err)
			}
		})
	}
}
