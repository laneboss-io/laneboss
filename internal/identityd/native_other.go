//go:build !linux && !darwin

package identityd

func processTerminal(int) (int, bool, string, error) {
	return 0, false, "", processUnavailable()
}

func peerCredentials(int) (Peer, peerLifetime, error) {
	return Peer{}, nil, processUnavailable()
}
func nativeProcess(int) (process, error) {
	return process{}, processUnavailable()
}
