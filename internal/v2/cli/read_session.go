package cli

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func runInternalReader(ctx context.Context, call Invocation) (resultErr error) {
	if len(call.Args) != 0 || call.ProofFile == "" || call.SessionProofFile != "" || call.Stdin == nil || call.Stdout == nil {
		return integrateInputError("internal reader requires a fresh human.session proof and JSON read envelopes on stdin")
	}
	raw, err := ReadInput(call.ProofFile, api.MaxFrameBytes)
	if err != nil {
		return err
	}
	var proof api.ProofRef
	if err := api.DecodeObject(raw, &proof); err != nil {
		return err
	}
	session, err := integrateSessionRequest(call.Config, proof)
	if err != nil {
		return err
	}
	var connection client.SessionCaller = call.Client
	if call.Client == nil {
		socket := call.integrateSocket
		if socket == nil {
			socket = &integrateSocket{options: client.Options{Config: call.Config}}
			defer func() {
				if socket.connection != nil {
					resultErr = errors.Join(resultErr, socket.connection.Close())
				}
			}()
		}
		if socket.connection == nil {
			opened, err := client.Open(ctx, socket.options)
			if err != nil {
				return err
			}
			socket.connection = opened
		}
		connection = socket.connection
	}
	return client.PumpReadSession(ctx, connection, session, call.Stdin, call.Stdout)
}
