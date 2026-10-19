// Package linux verifies host-side Linux socket lifetimes. Socket credentials
// identify the connector, not a subsequent writer of a passed descriptor.
// The transport must independently check message credentials and reject rights.
package linux

import "laneboss.io/laneboss/internal/v2/api"

var _ api.PeerVerifier = (*Verifier)(nil)

func peerError(code api.ErrorCode, message string) *api.Error {
	return &api.Error{Code: code, Message: message,
		Instead: "Use the installed host service and a live, bound run endpoint.",
		Owner:   "lb-v2-identity"}
}
