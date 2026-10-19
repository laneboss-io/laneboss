//go:build linux

package admin

import (
	"context"
	"net"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// SpendContext authenticates the same fixed native administrator path as
// enrollment. The service consumes only a reading; no tool path crosses IPC.
func SpendContext(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, connection api.ConnectionContext, frame api.FrameContext) (context.Context, error) {
	if nilEnrollmentPort(connection) || nilEnrollmentPort(frame) {
		return nil, failure(api.CodeForbidden, "spend reading lacks its native connection and frame")
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
		return nil, failure(api.CodeForbidden, "spend reading uses a foreign administrator socket")
	}
	if err := api.ValidateBinding(installed, endpoint.Config, endpoint.Helper.Version); err != nil {
		return nil, err
	}
	verify := func() error {
		if err := wire.VerifyAdministrator(ctx, endpoint, connection, frame); err != nil {
			return err
		}
		current, err := loadInstallation(endpoint.Config)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, binding) {
			return failure(api.CodeVersion, "spend reading installation changed")
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
	if request.Method != "spend_reconcile" {
		return nil, failure(api.CodeForbidden, "spend context requires its fixed native method")
	}
	var reading api.SpendReading
	if err := decodeStrict(request.Params, &reading); err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, enrollmentChannelKey{}, &enrollmentChannel{endpoint: endpoint, human: installed, verify: verify})
	return bindSpendReading(ctx, endpoint, reading)
}
