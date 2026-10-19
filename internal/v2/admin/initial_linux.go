//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	grantmanifest "laneboss.io/laneboss/internal/v2/grants/manifest"
)

// InitialContext bridges the service-owned native listener. It authenticates
// the actual socket, installed root helper and every frame; labels are unused.
func InitialContext(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, connection api.ConnectionContext, frame api.FrameContext) (context.Context, error) {
	if nilEnrollmentPort(connection) || nilEnrollmentPort(frame) {
		return nil, failure(api.CodeForbidden, "initial publication lacks its actual native connection and frame")
	}
	binding, err := loadInstallation(endpoint.Config)
	if err != nil {
		return nil, err
	}
	if err := validateEnrollmentEndpoint(endpoint, binding); err != nil {
		return nil, err
	}
	if err := verifyEnrollmentServiceIDs(binding); err != nil {
		return nil, err
	}
	socket, ok := connection.Conn().(*net.UnixConn)
	installed := connection.Binding()
	if !ok || socket.LocalAddr().String() != endpoint.Socket || installed.Socket != endpoint.Socket || installed.Config != endpoint.Config || installed.Class != api.EndpointHuman || installed.ServiceUID != endpoint.ServiceUID || installed.ArtifactSHA256 != endpoint.Helper.SHA256 || installed.InstallationGeneration != endpoint.InstallationGeneration {
		return nil, failure(api.CodeForbidden, "initial publication uses a foreign socket")
	}
	if err := api.ValidateBinding(installed, endpoint.Config, endpoint.Helper.Version); err != nil {
		return nil, err
	}
	verify := func() error {
		// Publication uses the same installed root daemon as enrollment. The
		// service cannot inspect a root process's mapped executable; the native
		// unit, lifetime, frame writer and protected artifact proof is shared.
		if err := wire.VerifyAdministrator(ctx, endpoint, connection, frame); err != nil {
			return err
		}
		current, err := loadInstallation(endpoint.Config)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, binding) {
			return failure(api.CodeVersion, "initial publication installation changed")
		}
		return checkEnrollmentSocket(endpoint.Socket, binding.Service)
	}
	if err := verify(); err != nil {
		return nil, err
	}
	var request helperRequest
	if err := decodeStrict(frame.Bytes(), &request); err != nil {
		return nil, err
	}
	if err := validateEnrollmentEnvelope(request, endpoint); err != nil {
		return nil, err
	}
	if request.Method != "initial_publish" {
		return nil, failure(api.CodeForbidden, "initial publication context requires its fixed native method")
	}
	var input InitialRequest
	if err := decodeStrict(request.Params, &input); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, enrollmentChannelKey{}, &enrollmentChannel{endpoint: endpoint, verify: verify, human: connection.Binding(), initialRequest: &input}), nil
}

func loadInitialDirectory(path string, request InitialRequest, config string) (initialBundle, error) {
	return loadInitialDirectoryObserved(nil, path, request, config)
}

func loadInitialDirectoryObserved(ctx context.Context, path string, request InitialRequest, config string) (initialBundle, error) {
	var empty initialBundle
	raw, err := readInitialProtectedObserved(ctx, path, api.MaxFrameBytes)
	if err != nil {
		return empty, err
	}
	var manifest InitialManifest
	if err := api.DecodeObject(raw, &manifest); err != nil {
		return empty, err
	}
	if len(manifest.Objects) == 0 || len(manifest.Objects) > 512 {
		return empty, failure(api.CodeInvalid, "initial object count exceeds its bound")
	}
	objects := map[api.ID][]byte{}
	var total int64
	for _, ref := range manifest.Objects {
		if !initialRef(ref) || objects[ref.ID] != nil {
			return empty, failure(api.CodeInvalid, "initial object inventory differs")
		}
		total += ref.Bytes
		if total > 64<<20 {
			return empty, failure(api.CodeBudget, "initial object staging exceeds its bound")
		}
		data, err := readInitialProtectedObserved(ctx, filepath.Join(filepath.Dir(path), "initial-objects", string(ref.ID)), ref.Bytes)
		if err != nil {
			return empty, err
		}
		objects[ref.ID] = data
	}
	return initialStage(ctx, "bundle_validate", func() (initialBundle, error) {
		return validateInitialObserved(ctx, request.Manifest, raw, objects, config)
	})
}

func loadInitialInstalled(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, request InitialRequest) (initialBundle, error) {
	var empty initialBundle
	if err := CheckEnrollmentChannel(ctx, endpoint); err != nil {
		return empty, err
	}
	binding, err := loadInstallation(endpoint.Config)
	if err != nil {
		return empty, err
	}
	if err := validateEnrollmentEndpoint(endpoint, binding); err != nil {
		return empty, err
	}
	return loadInitialBoundObserved(ctx, binding, request)
}

func loadInitialBound(binding installation, request InitialRequest) (initialBundle, error) {
	return loadInitialBoundObserved(nil, binding, request)
}

func loadInitialBoundObserved(ctx context.Context, binding installation, request InitialRequest) (initialBundle, error) {
	var empty initialBundle
	base := filepath.Join(filepath.Dir(binding.binaryPath()), "runtime", binding.Config)
	raw, err := readInitialProtectedObserved(ctx, filepath.Join(base, "initial-ref.json"), api.MaxFrameBytes)
	if err != nil {
		return empty, err
	}
	var installed InitialRequest
	if err := api.DecodeObject(raw, &installed); err != nil {
		return empty, err
	}
	if installed != request {
		return empty, failure(api.CodeForbidden, "initial request differs from the protected installed publication")
	}
	b, err := loadInitialDirectoryObserved(ctx, filepath.Join(base, "initial.json"), installed, binding.Config)
	if err != nil {
		return empty, err
	}
	for _, selected := range []struct {
		name string
		ref  api.BlobRef
	}{{"manifest.json", b.manifest.Runtime}, {"launch-enrollment.json", b.manifest.Launch}} {
		data, err := readInitialProtectedObserved(ctx, filepath.Join(base, selected.name), selected.ref.Bytes)
		if err != nil {
			return empty, err
		}
		if int64(len(data)) != selected.ref.Bytes || digestBytes(data) != selected.ref.SHA256 {
			return empty, failure(api.CodeIntegrity, "initial publication differs from installed launch inputs")
		}
	}
	var runtime api.RuntimeManifest
	if err := api.DecodeObject(b.objects[b.manifest.Runtime.ID], &runtime); err != nil {
		return empty, err
	}
	if runtime.Artifact.SHA256 != binding.Artifact.SHA256 || runtime.Artifact.Version != binding.Release.Version {
		return empty, failure(api.CodeIntegrity, "initial runtime differs from the installed release")
	}
	return b, nil
}

func readInitialProtected(path string, limit int64) ([]byte, error) {
	return readProtectedMode(path, limit, 0444)
}

func readInitialProtectedObserved(ctx context.Context, path string, limit int64) ([]byte, error) {
	return initialStage(ctx, "protected_read", func() ([]byte, error) {
		return readInitialProtected(path, limit)
	})
}

// Validation is a root-only fixed helper mode for the installer before it
// publishes any service state. It executes no worker, model or owner request.
func RunInitialValidation(ctx context.Context, config string, args []string, output io.Writer) error {
	if err := verifyHelperIDs(os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid()); err != nil {
		return err
	}
	if err := contextError(ctx); err != nil {
		return err
	}
	if !validConfig(config) || len(args) != 4 || args[0] != "--validate-initial" || args[2] != "--initial-ref" || output == nil {
		return failure(api.CodeInvalid, "initial validation requires its fixed protected input files")
	}
	raw, err := readInitialProtected(args[3], api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var request InitialRequest
	if err := api.DecodeObject(raw, &request); err != nil {
		return err
	}
	b, err := loadInitialDirectory(args[1], request, config)
	if err != nil {
		return err
	}
	if err := grantmanifest.Root(b.profiles, time.Now()); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		Valid    bool        `json:"valid"`
		Manifest api.BlobRef `json:"manifest"`
		ID       api.ID      `json:"id"`
	}{true, b.ref, b.manifest.ID})
}
