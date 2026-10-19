package client

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type SessionCaller interface {
	Call(context.Context, api.Request) (api.Response, error)
}

func sessionInvalid(message string) error {
	return &api.Error{Code: api.CodeInvalid, Owner: "lb-v2-integrate", Message: message,
		Instead: "Use the exact public read envelope and installed session binding."}
}

// ExchangeRead retains the typed public response, including a refused reply.
// Read authority remains on the authenticated connection supplied by its owner.
func ExchangeRead(ctx context.Context, conn SessionCaller, request api.Request, out io.Writer) error {
	if request.Method == "event.tail" {
		var tail api.EventTailRequest
		if err := api.DecodeObject(request.Params, &tail); err != nil {
			return err
		}
		if !wire.ValidID(string(tail.LifeID)) || tail.Run == 0 || uint64(tail.Run) > 1<<53-1 || tail.Follow {
			return sessionInvalid("session reader requires one explicit life/run and bounded event pages")
		}
	}
	prepared, err := PrepareRequest(request)
	if err != nil {
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	response, err := conn.Call(callCtx, prepared)
	if err != nil {
		return err
	}
	if response.Protocol != api.Protocol || response.Schema != api.SchemaVersion || response.RequestID != prepared.RequestID || (response.Error == nil) == (len(response.Result) == 0) {
		return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-service", Message: "invalid session response envelope",
			Instead: "Retain the command and repair the installed client/service generation."}
	}
	if response.Error == nil {
		result := reflect.New(api.Methods[prepared.Method].Response).Interface()
		if err := api.DecodeObject(response.Result, result); err != nil {
			return &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-service", Message: "session reply has the wrong typed shape",
				Instead: "Retain the raw response and repair the installed service."}
		}
	}
	if err := json.NewEncoder(out).Encode(response); err != nil {
		return err
	}
	if response.Error != nil {
		return response.Error
	}
	return nil
}

// PumpReadSession uses the caller's one installed connection. The caller owns
// its close; the service alone verifies and consumes the human.session proof.
func PumpReadSession(ctx context.Context, conn SessionCaller, session api.Request, in io.Reader, out io.Writer) error {
	if conn == nil || session.Method != "human.session" || session.Proof == nil {
		return sessionInvalid("reader requires its human.session prelude on one connection")
	}
	if err := ExchangeRead(ctx, conn, session, out); err != nil {
		return err
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), api.MaxFrameBytes)
	for scanner.Scan() {
		var request api.Request
		if err := api.DecodeObject(scanner.Bytes(), &request); err != nil {
			return err
		}
		spec, exists := api.Methods[request.Method]
		if !exists || spec.Mutation && !api.HumanSessionMethod(request.Method) || request.Proof != nil || request.Config != session.Config {
			return sessionInvalid("session reader refuses foreign config, ambient proof or authority mutation")
		}
		if err := ExchangeRead(ctx, conn, request, out); err != nil {
			return err
		}
	}
	return scanner.Err()
}
