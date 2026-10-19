package cli

import (
	"context"
	"laneboss.io/laneboss/internal/v2/assembly"

	"laneboss.io/laneboss/internal/v2/secrets"
)

func runInternalCredential(ctx context.Context, call Invocation) error {
	if len(call.Args) > 0 && call.Args[0] == "--native-owner" {
		flags := integrateFlags(call)
		flags.Bool("native-owner", false, "fixed installed native credential owner")
		installation := flags.String("installation", "", "protected installation")
		key := flags.String("key-file", "", "systemd credential key mount")
		if err := integrateParse(flags, call.Args); err != nil {
			return err
		}
		return assembly.RunCredentialBroker(ctx, call.Config, *installation, *key)
	}
	return secrets.RunInternal(ctx, call.Config, call.Args)
}
