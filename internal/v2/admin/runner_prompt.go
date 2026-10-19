package admin

import (
	"context"
	"errors"
	"io"
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

type runnerPromptRequest struct {
	LeaseID    api.ID             `json:"lease_id"`
	SpecSHA256 api.Digest         `json:"spec_sha256"`
	Cause      api.InternalIntent `json:"cause"`
}

type runnerPromptReceipt struct {
	LeaseID    api.ID      `json:"lease_id"`
	SpecSHA256 api.Digest  `json:"spec_sha256"`
	Prompt     api.BlobRef `json:"prompt"`
}

type runnerPromptEnd struct {
	Prompt api.BlobRef `json:"prompt"`
	Chunks int         `json:"chunks"`
}

type runnerPromptTransfer struct {
	Request runnerPromptRequest
	Ref     api.BlobRef
	Data    []byte
}

type runnerPrompt struct {
	request runnerPromptRequest
	ref     api.BlobRef
	file    *os.File
}

func helperInput(params any) any {
	if transfer, ok := params.(runnerPromptTransfer); ok {
		return transfer.Request
	}
	return params
}

func writeHelperInput(writer io.Writer, params any) error {
	transfer, ok := params.(runnerPromptTransfer)
	if !ok {
		return nil
	}
	if transfer.Ref.Class != "prompt" || transfer.Ref.Bytes < 1 || transfer.Ref.Bytes > api.MaxObjectBytes ||
		int64(len(transfer.Data)) != transfer.Ref.Bytes || digestBytes(transfer.Data) != transfer.Ref.SHA256 {
		return failure(api.CodeIntegrity, "runner prompt transfer differs from its committed bytes")
	}
	chunks := 0
	for offset := 0; offset < len(transfer.Data); {
		end := min(offset+api.MaxChunkBytes, len(transfer.Data))
		data := transfer.Data[offset:end]
		if err := writeFrame(writer, api.BlobChunk{ObjectID: transfer.Ref.ID, Offset: int64(offset), Data: data, SHA256: digestBytes(data)}); err != nil {
			return err
		}
		chunks++
		offset = end
	}
	return writeFrame(writer, runnerPromptEnd{Prompt: transfer.Ref, Chunks: chunks})
}

func (s *Service) registerRunnerPrompt(ctx context.Context, scope api.Scope, handoff api.PreparedSpecHandoff) error {
	if handoff.Spec.Runner == nil {
		return nil
	}
	ref := handoff.Spec.Runner.Prompt
	if ref.Class != "prompt" {
		return failure(api.CodeIntegrity, "runner prompt is not its retained prompt object")
	}
	data, err := s.readLaunchObject(ctx, scope, ref, handoff.OperationID, handoff.Spec.Target.LifeID, true)
	if err != nil {
		return err
	}
	defer clear(data)
	request := runnerPromptRequest{LeaseID: handoff.Spec.UIDLeaseID, SpecSHA256: handoff.SpecSHA256, Cause: handoff.Cause}
	var receipt runnerPromptReceipt
	if err := s.call(ctx, "runner_prompt", runnerPromptTransfer{Request: request, Ref: ref, Data: data}, &receipt); err != nil {
		return err
	}
	if receipt.LeaseID != request.LeaseID || receipt.SpecSHA256 != request.SpecSHA256 || receipt.Prompt != ref {
		return failure(api.CodeIntegrity, "helper runner prompt receipt changed its retained input")
	}
	return nil
}

func (m *leaseManager) closeRunnerPrompt(id api.ID) error {
	input := m.prompts[id]
	if input == nil {
		return nil
	}
	if err := input.file.Close(); err != nil {
		return errors.Join(failure(api.CodeContainmentUnknown, "runner prompt ownership could not close"), err)
	}
	delete(m.prompts, id)
	return nil
}
