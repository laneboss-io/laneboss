//go:build darwin

package wire

import (
	"net"
	"syscall"

	"laneboss.io/laneboss/internal/v2/api"
)

func EnableCredentials(syscall.Conn) error {
	return api.NotImplemented("lb-v2-service", "native per-message writer evidence")
}
func EnableRawCredentials(syscall.RawConn) error {
	return api.NotImplemented("lb-v2-service", "native per-message writer evidence")
}
func PeerCredentials(*net.UnixConn) (SocketPeer, error) {
	return SocketPeer{}, api.NotImplemented("lb-v2-service", "native per-message writer evidence")
}

func serverCredentials(connection *net.UnixConn, _ bool) (SocketPeer, error) {
	return PeerCredentials(connection)
}

type credentialReader struct {
	connection *net.UnixConn
	expected   SocketPeer
}

func (*credentialReader) Read([]byte) (int, error) {
	return 0, api.NotImplemented("lb-v2-service", "native per-message writer evidence")
}
