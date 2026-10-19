// Package box implements the command interface for disposable spot test machines.
package box

import (
	"errors"
	"fmt"
	"io"
	"os"

	"laneboss.io/laneboss/internal/boxcfg"
	"laneboss.io/laneboss/internal/boxcore"
)

// Run parses a box command, calls the service and returns its process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	home, err := os.UserHomeDir()
	return run(args, stdin, stdout, stderr, environment{
		getenv: os.Getenv, userHome: home, homeErr: err,
	}, buildService)
}

func usageError(stderr io.Writer, err error) int {
	fmt.Fprint(stderr, usage)
	fmt.Fprintln(stderr, "laneboss box: error: "+err.Error())
	return boxcore.ExitUsage
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, env environment, build builder) (code int) {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "laneboss box: internal error")
			code = boxcore.ExitInternal
		}
	}()
	a, help, err := parse(args)
	if err != nil {
		return usageError(stderr, err)
	}
	if help {
		if _, err := io.WriteString(stdout, usage); err != nil {
			fmt.Fprintln(stderr, "laneboss box: the output cannot be written")
			return boxcore.ExitInternal
		}
		return boxcore.ExitOK
	}
	env = env.defaults()
	if env.homeErr != nil {
		fmt.Fprintln(stderr, "laneboss box: the user home cannot be found")
		return boxcore.ExitUsage
	}
	if !a.set["config"] {
		a.config = env.getenv("LANEBOSS_CONFIG")
	}
	configEnv := boxcfg.EnvFrom(env.getenv, env.userHome)
	file, err := env.locate(boxcfg.LocateOptions{
		Flag: a.boxConfig, EnvValue: env.getenv("LANEBOSS_BOX_CONFIG"),
		ConfigName: a.config, Home: configEnv.Home,
	})
	if err == nil {
		var cfg *boxcore.Config
		cfg, err = env.load(file, configEnv)
		if err == nil {
			return configured(a, cfg, stdin, stdout, stderr, env, build)
		}
	}
	if a.command == "check" {
		if _, writeErr := fmt.Fprintln(stdout, "FAIL: config"); writeErr != nil {
			fmt.Fprintln(stderr, "laneboss box: the output cannot be written")
			return boxcore.ExitInternal
		}
	}
	// The config package supplies fixed, value-free diagnostic text.
	fmt.Fprintln(stderr, "laneboss box: "+err.Error())
	return boxcore.ExitUsage
}

func configured(a arguments, cfg *boxcore.Config, stdin io.Reader, stdout, stderr io.Writer, env environment, build builder) (code int) {
	if a.command == "check" {
		if a.set["provider"] {
			var err error
			a.provider, err = providerFor(cfg, a.provider)
			if err != nil {
				return usageError(stderr, err)
			}
		}
		return check(cfg, a.provider, stdout, stderr, env)
	}
	d := buildDeps{stdin: stdin, stdout: stdout, stderr: stderr, env: env}
	var events []map[string]any
	if a.command == "list" || a.command == "end" && !a.set["provider"] {
		var err error
		d.ledger, err = env.openLedger(cfg, stderr)
		if err != nil {
			return usageError(stderr, errors.New("the ledger cannot be read"))
		}
		events, err = d.ledger.Events()
		if err != nil {
			return usageError(stderr, errors.New("the ledger cannot be read"))
		}
		if a.command == "end" {
			if launch := lastLaunch(events, a.instance); launch != nil {
				value, present := launch["provider"]
				if !present {
					a.provider = "aws"
				} else if provider, ok := value.(string); ok && provider != "" {
					a.provider = provider
				} else {
					return usageError(stderr, errors.New("the ledger provider is not accepted"))
				}
			}
		}
	}
	var err error
	a.provider, err = providerFor(cfg, a.provider)
	if err != nil {
		return usageError(stderr, err)
	}
	if a.command == "launch" || a.command == "run" {
		if err := a.placement(cfg, env.getenv); err != nil {
			return usageError(stderr, err)
		}
	}
	ctx, stop := withSignals(env, stderr)
	defer stop()
	var runOptions boxcore.RunOptions
	if a.command == "run" {
		var cleanup func() error
		runOptions, cleanup, err = prepareRun(ctx, a, env)
		if err != nil {
			return usageError(stderr, err)
		}
		defer func() {
			if err := cleanup(); err != nil {
				fmt.Fprintln(stderr, "laneboss box: the source archive cannot be removed")
				if code == boxcore.ExitOK {
					code = boxcore.ExitInternal
				}
			}
		}()
	}
	svc, err := build(cfg, d)
	if err != nil || svc == nil {
		fmt.Fprintln(stderr, "laneboss box: the service cannot be prepared")
		return boxcore.ExitUsage
	}
	switch a.command {
	case "launch":
		r, err := svc.Launch(ctx, boxcore.LaunchOptions{Request: a.request, DryRun: a.dry})
		if err != nil && r.ExitCode == boxcore.ExitOK {
			r.ExitCode = boxcore.ExitInternal
		}
		return finish(r.ExitCode, err, printLaunch(stdout, a, r), stderr)
	case "run":
		r, err := svc.Run(ctx, runOptions)
		if err != nil && r.ExitCode == boxcore.ExitOK {
			r.ExitCode = boxcore.ExitInternal
		}
		return finish(r.ExitCode, err, printRun(stdout, a.format, r), stderr)
	case "end":
		r, err := svc.End(ctx, boxcore.EndOptions{
			Provider: a.provider, ID: a.instance, Address: a.address,
			BoundSec: a.bound, PollSec: 15,
		})
		if err != nil && r.ExitCode == boxcore.ExitOK {
			r.ExitCode = boxcore.ExitInternal
		}
		return finish(r.ExitCode, err, printEnd(stdout, stderr, a, r), stderr)
	case "list":
		rows, err := svc.List(ctx, boxcore.ListOptions{
			Provider: a.provider, Orphans: a.orphans, OlderThanMin: a.older,
		})
		if err != nil {
			fmt.Fprintln(stderr, "laneboss box: the boxes cannot be listed")
			return boxcore.ExitUsage
		}
		return finish(boxcore.ExitOK, nil, printList(stdout, a.format, rows, events), stderr)
	case "sweep":
		r, err := svc.Sweep(ctx, boxcore.SweepOptions{
			Provider: a.provider, OlderThanMin: a.older, Delete: a.delete,
		})
		if err != nil {
			fmt.Fprintln(stderr, "laneboss box: the sweep could not finish")
			return boxcore.ExitUsage
		}
		return finish(boxcore.ExitOK, nil, printSweep(stdout, a.format, r), stderr)
	}
	return boxcore.ExitInternal
}

func lastLaunch(events []map[string]any, id string) map[string]any {
	for i := len(events) - 1; i >= 0; i-- {
		if events[i]["event"] == "LAUNCHED" && events[i]["instance_id"] == id {
			return events[i]
		}
	}
	return nil
}

func finish(code int, serviceErr, outputErr error, stderr io.Writer) int {
	if serviceErr != nil {
		fmt.Fprintln(stderr, "laneboss box: the operation did not finish cleanly")
		if code == boxcore.ExitOK {
			code = boxcore.ExitInternal
		}
	}
	if outputErr != nil {
		fmt.Fprintln(stderr, "laneboss box: the output cannot be written")
		return boxcore.ExitInternal
	}
	return code
}
