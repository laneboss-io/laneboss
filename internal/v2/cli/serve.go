package cli

import (
	"context"
	"laneboss.io/laneboss/internal/v2/assembly"
)

func integrateRunServe(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	installation := flags.String("installation", "", "administrator-installed service configuration file")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	bindingFile := ""
	if call.Client != nil {
		bindingFile = call.Client.Options.BindingFile
	} else if call.integrateSocket != nil {
		bindingFile = call.integrateSocket.options.BindingFile
	}
	return assembly.Serve(ctx, assembly.Options{Config: call.Config,
		BindingFile: bindingFile, InstallationFile: *installation})
}
