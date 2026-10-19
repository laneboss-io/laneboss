package dataworker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/testjob"
)

// RunInternal is a trusted worker mode, never an arbitrary command endpoint.
// A label/argument cannot replace an installed binding and authenticated lease.
func RunInternal(ctx context.Context, config string, args []string) (resultErr error) {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if !manifest.Config(config) || len(args) != 4 || args[0] != "--binding" || args[1] != "/runtime/laneboss-worker.json" || args[2] != "--lease" || !manifest.ValidID(api.ID(args[3])) {
		return manifest.Invalid("invalid internal worker configuration or arguments")
	}
	// Resolve the principal from the actual credential-pinned worker endpoint.
	// An argv lease or an on-disk actor label cannot manufacture that authority.
	connection, err := client.OpenWorker(ctx, client.Options{Config: config, BindingFile: args[1]}, api.ID(args[3]))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, connection.Close()) }()
	p := connection.Principal()
	if p.Lease.Kind == "export" || p.Lease.Kind == "test" {
		input, err := wire.ReadReviewInput(p.Lease.Input)
		if err != nil {
			return err
		}
		scope := api.Scope{Config: config, Actor: p.Record.Actor, LaunchID: p.Record.ID,
			EndpointGeneration: p.Record.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
		if p.Lease.Kind == "test" {
			var selected testjob.Input
			if api.DecodeObject(input, &selected) != nil || !manifest.ValidID(selected.Plan.Executable.ID) {
				return manifest.Invalid("TestChild has no enrolled executable selector")
			}
			executable, err := os.Open("/runtime/" + string(selected.Plan.Executable.ID))
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, executable.Close()) }()
			directory, err := os.MkdirTemp("/tmp", "test-child-")
			if err != nil {
				return err
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
			_, err = RunInternalJob(ctx, config, args, TestJob{Principal: p, Scope: scope, Bootstrap: sealedWorkerBootstrap{WorkerBootstrap: connection, input: input},
				Read: connection.Read, Clock: nativeArchiveClock{}, Workspace: root, Directory: directory, Executable: executable})
			return err
		}
		_, err = RunInternalJob(ctx, config, args, ReviewJob{Principal: p, Scope: scope,
			Bootstrap: sealedWorkerBootstrap{WorkerBootstrap: connection, input: input}, Read: connection.Read, Clock: nativeArchiveClock{}})
		return err
	}
	if p.Lease.Kind != "materialize" && p.Lease.Kind != "archive" && p.Lease.Kind != "usage" && p.Lease.Kind != "channel" {
		return &api.Error{Code: api.CodeUnsupported, Owner: "lb-v2-grants", Message: "fixed native worker job is not supported", Instead: "Use an implemented leased worker kind without changing this session binding."}
	}
	if p.Lease.Kind == "materialize" && p.Lease.Input.Class != "materialize_input" || p.Lease.Kind == "archive" && p.Lease.Input.Class != "archive_input" ||
		p.Lease.Kind == "usage" && p.Lease.Input.Class != "usage_input" || p.Lease.Kind == "channel" && p.Lease.Input.Class != "channel_input" {
		return manifest.Invalid("native worker input class differs from its fixed job")
	}
	input, err := wire.ReadWorkerInput(p.Lease.Input)
	if err != nil {
		return err
	}
	scope := api.Scope{Config: config, Actor: p.Record.Actor, LaunchID: p.Record.ID, EndpointGeneration: p.Record.EndpointGeneration, PolicyGeneration: p.Record.PolicyGeneration}
	bootstrap := sealedWorkerBootstrap{WorkerBootstrap: connection, input: input}
	clock := nativeArchiveClock{}
	if p.Lease.Kind == "channel" {
		_, err = RunInternalJob(ctx, config, args, ChannelWorkerJob{Principal: p, Scope: scope, Bootstrap: bootstrap, Channel: connection,
			Read: connection.Read, Clock: clock, Material: nativeChannelMaterial(p)})
		return err
	}
	if p.Lease.Kind == "usage" {
		var selected api.UsageCredentialInput
		if err := api.DecodeObject(input, &selected); err != nil {
			return err
		}
		if !manifest.ValidID(selected.Request.Executable.ID) {
			return manifest.Invalid("usage worker executable has no enrolled runtime ID")
		}
		executable, err := os.Open("/runtime/" + string(selected.Request.Executable.ID))
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, executable.Close()) }()
		home, err := os.Open("/job/home")
		if err != nil {
			return err
		}
		defer func() { resultErr = errors.Join(resultErr, home.Close()) }()
		_, err = RunInternalJob(ctx, config, args, UsageJob{Principal: p, Scope: scope, Bootstrap: bootstrap, Executable: executable, Home: home, Clock: clock})
		return err
	}
	if p.Lease.Kind == "archive" {
		_, err = RunInternalJob(ctx, config, args, ArchiveJob{Principal: p, Scope: scope, Bootstrap: bootstrap, Read: connection.Read, Sink: connection, Clock: clock})
		return err
	}
	var materialization MaterializationInput
	if err := api.DecodeObject(input, &materialization); err != nil {
		return err
	}
	if err := workerMaterializationInput(materialization, p, clock.Now()); err != nil {
		return err
	}
	roots, err := openNativeMaterializationRoots(p, materialization.Storage)
	if err != nil {
		return err
	}
	defer func() {
		for _, root := range roots {
			resultErr = errors.Join(resultErr, root.Close())
		}
	}()
	copies, err := openNativeMaterializationCopies(p, materialization.Storage)
	if err != nil {
		return err
	}
	defer func() {
		for _, roots := range copies {
			resultErr = errors.Join(resultErr, roots.Source.Close(), roots.Destination.Close())
		}
	}()
	_, err = RunInternalJob(ctx, config, args, MaterializationJob{Principal: p, Scope: scope, Bootstrap: bootstrap,
		Source: roots[0], Workspace: roots[1], Home: roots[2], Copies: copies, Read: connection.Read, Clock: clock})
	return err
}

// The local sealed bytes and the current authenticated service response must
// agree exactly. Neither one substitutes for the other's evidence.
type sealedWorkerBootstrap struct {
	api.WorkerBootstrap
	input []byte
}

func (b sealedWorkerBootstrap) WorkerInput(ctx context.Context, scope api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	input, err := b.WorkerBootstrap.WorkerInput(ctx, scope, request)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if !bytes.Equal(input.Bytes, b.input) {
		return api.WorkerJobInput{}, &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-grants", Message: "authenticated worker input differs from its inherited sealed bytes", Instead: "Retain the failed job and reconcile its original helper projection."}
	}
	return input, nil
}

type nativeArchiveClock struct{}

func (nativeArchiveClock) Now() time.Time { return time.Now() }

// RunInternalJob is called after the installed native bootstrap supplies the
// actual worker session and held roots. No public command or protocol is added.
func RunInternalJob(ctx context.Context, config string, args []string, job any) (api.WorkerResultReceipt, error) {
	var principal api.WorkerPrincipal
	switch value := job.(type) {
	case MaterializationJob:
		principal = value.Principal
	case ArchiveJob:
		principal = value.Principal
	case ChannelWorkerJob:
		principal = value.Principal
	case UsageJob:
		principal = value.Principal
	case ReviewJob:
		principal = value.Principal
	case TestJob:
		principal = value.Principal
	default:
		return api.WorkerResultReceipt{}, manifest.Invalid("fixed worker received an unsupported native job capability")
	}
	if !manifest.Config(config) || len(args) != 4 || args[0] != "--binding" || args[1] != "/runtime/laneboss-worker.json" || args[2] != "--lease" || api.ID(args[3]) != principal.Lease.ID || config != principal.Endpoint.Config {
		return api.WorkerResultReceipt{}, manifest.Invalid("fixed worker entry differs from its installed job binding")
	}
	switch value := job.(type) {
	case MaterializationJob:
		return RunMaterialization(ctx, value)
	case ArchiveJob:
		return RunArchive(ctx, value)
	case ChannelWorkerJob:
		return RunChannelWorker(ctx, value)
	case UsageJob:
		return RunUsage(ctx, value)
	case ReviewJob:
		if value.Principal.Lease.Kind == "test" {
			return RunChecks(ctx, value)
		}
		return RunReview(ctx, value)
	case TestJob:
		return RunTest(ctx, value)
	}
	return api.WorkerResultReceipt{}, manifest.Invalid("fixed worker has no native job")
}
