package boxaws

import (
	"context"
	"io"

	"laneboss.io/laneboss/internal/boxcore"
	"laneboss.io/laneboss/internal/boxexec"
)

type transport struct {
	run      boxexec.Runner
	user     string
	identity string
	address  string
	options  boxcore.TransportOptions
}

// Transport returns SSH transport for this box.
func (p *provider) Transport(b boxcore.Box, o boxcore.TransportOptions) boxcore.Transport {
	return &transport{run: p.run, user: p.cfg.SSHUser, identity: p.cfg.SSHIdentity,
		address: b.Address, options: o}
}

// Exec passes one command and its streams to SSH, separating connection errors.
func (t *transport) Exec(ctx context.Context, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if t.run == nil {
		return -1, boxcore.NewError(boxcore.KindTransport, "ssh", "", "no process runner", nil)
	}
	args := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new"}
	if t.options.KnownHostsFile != "" {
		args = append(args, "-o", "UserKnownHostsFile="+t.options.KnownHostsFile)
	}
	args = append(args, "-o", "IdentitiesOnly=yes", "-i", t.identity, t.user+"@"+t.address, command)
	result, err := t.run.Run(ctx, boxexec.Cmd{Name: "ssh", Args: args, Env: boxexec.CleanEnv(nil),
		Stdin: stdin, Stdout: stdout, Stderr: stderr})
	if err != nil || result.Code == 255 {
		return -1, boxcore.NewError(boxcore.KindTransport, "ssh", "", "SSH transport failed", err)
	}
	return result.Code, nil
}
