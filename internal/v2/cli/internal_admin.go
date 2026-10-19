package cli

import (
	"context"
	"strings"

	"laneboss.io/laneboss/internal/v2/admin"
)

func runInternalHelper(ctx context.Context, call Invocation) error {
	if len(call.Args) > 0 && call.Args[0] == "--validate-initial" {
		return admin.RunInitialValidation(ctx, call.Config, call.Args, call.Stdout)
	}
	for _, argument := range call.Args {
		if strings.HasPrefix(argument, "--enroll-") || argument == "--installation" || argument == "--publish-initial" || argument == "--spend-reconcile" {
			return admin.RunEnrollment(ctx, call.Config, call.Args, call.Stdout)
		}
	}
	return admin.RunInternal(ctx, call.Config, call.Args)
}
