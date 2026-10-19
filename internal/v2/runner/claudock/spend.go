package claudock

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

// ParseSpendLine parses only a top-level vendor result. The caller must bind
// the bytes to the protected primary stream and the sealed vendor session.
// total_cost_usd is the result's reported turn total. cost_usd, modelUsage
// costUSD, CLI budgets and token-price multiplication cannot replace it.
func ParseSpendLine(line []byte, session string) (*api.VendorSpend, error) {
	if len(line) > maxRecordBytes || session == "" {
		return nil, failure(api.CodeIntegrity, "spend record lacks its bounded vendor session")
	}
	event, err := decodeRecord(line)
	if err != nil {
		return nil, err
	}
	return vendorSpend(event, session)
}

func vendorSpend(event map[string]any, session string) (*api.VendorSpend, error) {
	if !label(textValue(event["type"])) {
		return nil, failure(api.CodeIntegrity, "spend record has no typed vendor event")
	}
	if id, exists := event["session_id"]; exists && id != session {
		return nil, failure(api.CodeIntegrity, "spend record differs from the sealed vendor session")
	}
	if event["type"] != "result" {
		return nil, nil
	}
	id := textValue(event["uuid"])
	if event["session_id"] != session || !identifier(api.ID(id)) {
		return nil, failure(api.CodeIntegrity, "vendor result lacks its session and result identity")
	}
	if _, ok := event["is_error"].(bool); !ok {
		return nil, failure(api.CodeIntegrity, "vendor result lacks its typed error disposition")
	}
	amount, ok := event["total_cost_usd"].(json.Number)
	if !ok {
		return nil, failure(api.CodeIntegrity, "vendor result is missing total_cost_usd")
	}
	cost, err := api.USDMicros(string(amount), true)
	if err != nil {
		return nil, err
	}
	usage, ok := event["usage"].(map[string]any)
	if !ok {
		return nil, failure(api.CodeIntegrity, "vendor result lacks its usage record")
	}
	tokens := func(name string, required bool) (int64, error) {
		raw, exists := usage[name]
		if !exists && !required {
			return 0, nil
		}
		n, ok := raw.(json.Number)
		if !ok {
			return 0, failure(api.CodeIntegrity, "vendor usage has an untyped token count")
		}
		value, err := n.Int64()
		if err != nil || value < 0 || value > 1<<53-1 {
			return 0, failure(api.CodeIntegrity, "vendor usage token count is outside its bound")
		}
		return value, nil
	}
	result := &api.VendorSpend{SessionID: session, ResultID: id, CostMicros: cost}
	for _, item := range []struct {
		name     string
		required bool
		value    *int64
	}{
		{"input_tokens", true, &result.InputTokens}, {"output_tokens", true, &result.OutputTokens},
		{"cache_read_input_tokens", false, &result.CacheReadTokens}, {"cache_creation_input_tokens", false, &result.CacheCreationTokens},
	} {
		*item.value, err = tokens(item.name, item.required)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Service) SpendFromCapture(ctx context.Context, record api.CaptureRecord) ([]api.VendorSpend, error) {
	request, events, err := s.captured(ctx, record)
	if err != nil {
		return nil, err
	}
	result := []api.VendorSpend{}
	for _, event := range events {
		spend, err := vendorSpend(event, request.Session.VendorID)
		if err != nil {
			return nil, err
		}
		if spend != nil {
			result = append(result, *spend)
		}
	}
	return result, nil
}
