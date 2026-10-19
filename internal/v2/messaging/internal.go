package messaging

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func RunInternal(ctx context.Context, config string, args []string) error {
	// The frozen contracts have neither an installed channel resolver nor a
	// single-use worker lease/transport. A config string or argv must never
	// authorize delivery. Keep this mode closed until integration adds that
	// reviewed contract; see CONTRACTS.md. No file, socket or service is opened.
	return api.NotImplemented("lb-v2-messaging", "internal.channel")
}
