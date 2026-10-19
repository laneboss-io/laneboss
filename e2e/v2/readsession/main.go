// Command readsession keeps public reads on one installed client connection.
// It has no store, helper, credential signer or private service API access.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

type connection interface {
	Call(context.Context, api.Request) (api.Response, error)
	Close() error
}

type opener func(context.Context, client.Options) (connection, error)

func invalid(message string) error {
	return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-e2e", Message: message,
		Instead: "Use the exact public read envelope and installed session binding."}
}

func exchange(ctx context.Context, conn connection, request api.Request, out io.Writer) error {
	return client.ExchangeRead(ctx, conn, request, out)
}

func serve(ctx context.Context, options client.Options, proof api.ProofRef, in io.Reader, out io.Writer, open opener) (result error) {
	// Validate the session proof digest before opening any socket. Verification
	// and single-use consumption belong to installed identity/store, not here.
	key, err := client.NewRequestID()
	if err != nil {
		return err
	}
	session, err := client.PrepareRequest(api.Request{Config: options.Config, Method: "human.session",
		Params: json.RawMessage(`{}`), IdempotencyKey: key, Proof: &proof})
	if err != nil {
		return err
	}
	conn, err := open(ctx, options)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	return client.PumpReadSession(ctx, conn, session, in, out)
}

func run() error {
	config := flag.String("config", "", "one installed configuration")
	binding := flag.String("binding", "", "protected installed binding file")
	proofFile := flag.String("proof", "", "fresh protected human.session proof reference")
	flag.Parse()
	if flag.NArg() != 0 || *config == "" || *binding == "" || *proofFile == "" {
		return invalid("config, binding and proof files are required")
	}
	file, err := os.Open(*proofFile)
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(file, api.MaxFrameBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.Join(err, closeErr)
	}
	var proof api.ProofRef
	if err := api.DecodeObject(raw, &proof); err != nil {
		return err
	}
	return serve(context.Background(), client.Options{Config: *config, BindingFile: *binding}, proof,
		os.Stdin, os.Stdout, func(ctx context.Context, options client.Options) (connection, error) {
			return client.Open(ctx, options)
		})
}

func main() {
	if err := run(); err != nil {
		var typed *api.Error
		if !errors.As(err, &typed) {
			typed = &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-e2e", Message: "session reader failed",
				Instead: "Retain the process receipt and raw output."}
		}
		if encodeErr := json.NewEncoder(os.Stderr).Encode(typed); encodeErr != nil {
			fmt.Fprintln(os.Stderr, "cannot retain session error")
		}
		if typed.Code == api.CodeNotImplemented || typed.Code == api.CodePrerequisite || typed.Code == api.CodeUnavailable {
			os.Exit(69)
		}
		os.Exit(1)
	}
}
