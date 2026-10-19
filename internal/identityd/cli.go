package identityd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

const usage = "usage: laneboss service {run,status} --config NAME [--state-root PATH] [--runtime-root PATH] [--uid-connection-limit N] [--config-home PATH --human-uid UID --human-session PID:START] [--legacy-state PATH]"

// Run adds service lifecycle commands without changing existing CLI operations.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && (args[0] == "__launch_parent" || args[0] == "__launch_root") {
		return launchWorker(args, stdin, stdout, stderr)
	}
	if len(args) == 0 {
		return cliargs.Print(stderr, "laneboss service", usage, cliargs.Required("action"))
	}
	if args[0] == "--help" || args[0] == "-h" {
		fmt.Fprintln(stdout, usage+"\nRun the identity service as its dedicated OS user, or query its kernel-authenticated status.\nThe primary OS group is the configuration's caller group. See docs/service.md.")
		return 0
	}
	action := args[0]
	if action != "run" && action != "status" {
		return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject("action"))
	}
	options := Options{}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			fmt.Fprintln(stdout, usage+"\n--config NAME is required. Roots default to /var/lib/laneboss and /var/run/laneboss.\n--uid-connection-limit is for service run, defaults to 8, and accepts 1 through 32.\nRoot overrides are for provisioned installations and isolated fixtures; they grant no caller identity.")
			return 0
		}
		name, value, attached := strings.Cut(args[i], "=")
		if name != "--config" && name != "--state-root" && name != "--runtime-root" && name != "--uid-connection-limit" && name != "--config-home" && name != "--human-uid" && name != "--human-session" && name != "--legacy-state" || seen[name] {
			return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject(""))
		}
		seen[name] = true
		if !attached {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return cliargs.Print(stderr, "laneboss service", usage, cliargs.Expected(name))
			}
			i++
			value = args[i]
		}
		if value == "" {
			return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject(name))
		}
		switch name {
		case "--config":
			options.Config = value
		case "--state-root":
			options.StateRoot = value
		case "--runtime-root":
			options.RuntimeRoot = value
		case "--config-home":
			options.ConfigHome = value
		case "--legacy-state":
			options.LegacyState = value
		case "--human-uid":
			uid, err := strconv.ParseUint(value, 10, 32)
			if err != nil || uid == 0 || action != "run" {
				return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject(name))
			}
			options.HumanUID = uint32(uid)
		case "--human-session":
			pidText, start, ok := strings.Cut(value, ":")
			pid, err := strconv.Atoi(pidText)
			if !ok || err != nil || pid <= 1 || start == "" || action != "run" {
				return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject(name))
			}
			options.HumanSession = &ProcessRef{PID: pid, Start: start}
		case "--uid-connection-limit":
			limit, err := strconv.Atoi(value)
			if err != nil || limit < 1 || limit > MaxConnections || action != "run" {
				return cliargs.Print(stderr, "laneboss service", usage, cliargs.Reject(name))
			}
			options.UIDConnectionLimit = limit
		}
	}
	if options.Config == "" {
		return cliargs.Print(stderr, "laneboss service", usage, cliargs.Required("--config"))
	}
	if err := config.GuardNamed(options.Config); err != nil {
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	if action == "status" {
		if options.RuntimeRoot == "" {
			c, loadError := config.Load(options.Config)
			if loadError != nil {
				err = loadError
			} else {
				options.RuntimeRoot, _, err = config.IdentityService(c)
			}
		}
		var response Response
		if err == nil {
			response, err = Call(ctx, options, Request{Op: "whoami"})
		}
		if err == nil {
			err = json.NewEncoder(stdout).Encode(response)
		}
	} else {
		var server *Server
		server, err = Open(options)
		if err == nil {
			ready := struct {
				Version int         `json:"laneboss_service"`
				OK      bool        `json:"ok"`
				Socket  string      `json:"socket"`
				Service ServiceInfo `json:"service"`
			}{Version, true, server.Socket(), server.Info()}
			err = json.NewEncoder(stdout).Encode(ready)
			if err == nil {
				err = server.Serve(ctx)
			}
			err = errors.Join(err, server.Close())
		}
	}
	if err != nil {
		var scoped *ticket.Refusal
		if errors.As(err, &scoped) {
			fmt.Fprintln(stderr, "refused: "+scoped.Error())
			return 2
		}
		var selection *config.Error
		if errors.As(err, &selection) {
			fmt.Fprintln(stderr, selection.Prefix+": "+selection.Message)
			return selection.Code
		}
		var problem *failure
		if errors.As(err, &problem) {
			fmt.Fprintln(stderr, problem.text)
			return problem.code
		}
		fmt.Fprintln(stderr, "integrity problem: service operation failed")
		return 3
	}
	return 0
}
