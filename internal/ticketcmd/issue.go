// Package ticketcmd implements the human-only registration-ticket command.
package ticketcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/cliargs"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/identityd/ticket"
)

const usage = "usage: laneboss ticket issue --config NAME --level LEVEL --role ROLE [--ttl 10m]"

type options struct {
	config, role string
	level        int
	ttl          time.Duration
	help         bool
}

func parse(args []string) (options, error) {
	o := options{ttl: ticket.DefaultTTL}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		o.help = true
		return o, nil
	}
	if len(args) == 0 || args[0] != "issue" {
		return o, errors.New(cliargs.Reject(""))
	}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--help" || a == "-h" {
			o.help = true
			continue
		}
		label, value, attached := strings.Cut(a, "=")
		if label != "--config" && label != "--level" && label != "--role" && label != "--ttl" || seen[label] {
			return o, errors.New(cliargs.Reject(""))
		}
		seen[label] = true
		if !attached {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return o, errors.New(cliargs.Expected(label))
			}
			i++
			value = args[i]
		}
		switch label {
		case "--config":
			o.config = value
		case "--role":
			o.role = value
		case "--level":
			level, err := strconv.Atoi(value)
			if err != nil || level < 3 || level > 6 || strconv.Itoa(level) != value {
				return o, &ticket.Refusal{Reason: ticket.InvalidScope}
			}
			o.level = level
		case "--ttl":
			ttl, err := time.ParseDuration(value)
			if err != nil || !ticket.ValidTTL(ttl) {
				return o, &ticket.Refusal{Reason: ticket.InvalidTTL}
			}
			o.ttl = ttl
		}
	}
	if !o.help && (!seen["--config"] || !seen["--level"] || !seen["--role"]) {
		return o, errors.New(cliargs.Required("--config", "--level", "--role"))
	}
	return o, nil
}

// Run is fail-closed on the additive 0.7.0 branch. Part 1 supplies its OS-peer
// authenticated client through RunWithIssuer; it must not open a caller-owned
// database or use a client-controlled human flag as a replacement.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return RunWithIssuer(args, stdin, stdout, stderr, nil)
}

func RunWithIssuer(args []string, stdin io.Reader, stdout, stderr io.Writer, issuer ticket.Issuer) int {
	_ = stdin
	o, err := parse(args)
	if err != nil {
		var r *ticket.Refusal
		if errors.As(err, &r) {
			return printError(err, stderr)
		}
		return cliargs.Print(stderr, "laneboss ticket", usage, err.Error())
	}
	if o.help {
		if _, err := fmt.Fprintln(stdout, usage+"\n\nOnly the human at a real terminal may issue. The ticket is printed once; pass a private file path to start."); err != nil {
			return 70
		}
		return 0
	}
	if err := config.GuardNamed(o.config); err != nil {
		return printError(err, stderr)
	}
	c, err := config.Load(o.config)
	if err == nil {
		err = caller.RequireHuman(c)
	}
	if err == nil {
		var target caller.Principal
		target, _, err = caller.Role(c, o.role)
		if err != nil || target.Level != o.level {
			err = &ticket.Refusal{Reason: ticket.InvalidScope}
		}
	}
	if err == nil && issuer == nil {
		err = &ticket.Refusal{Reason: ticket.Unavailable}
	}
	var raw string
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		raw, err = issuer.Issue(ctx, ticket.Scope{Config: c.Name, Level: o.level, Role: o.role}, o.ttl)
		if err == nil && !ticket.Valid(raw) {
			err = &ticket.Refusal{Reason: ticket.Unavailable}
		}
	}
	if err != nil {
		return printError(err, stderr)
	}
	// No JSON wrapper or diagnostic duplicates the secret. A failed output is
	// a failed issue command; a fresh ticket is needed, never a second print.
	if n, err := io.WriteString(stdout, raw+"\n"); err != nil || n != len(raw)+1 {
		fmt.Fprintln(stderr, "internal error: the issued ticket could not be written once")
		return 70
	}
	return 0
}

func printError(err error, stderr io.Writer) int {
	var c *config.Error
	if errors.As(err, &c) {
		fmt.Fprintln(stderr, c.Prefix+": "+c.Message)
		return c.Code
	}
	var r *ticket.Refusal
	if !errors.As(err, &r) {
		r = &ticket.Refusal{Reason: ticket.Unavailable}
	}
	lines := strings.Split(r.Error(), "\n")
	fmt.Fprintln(stderr, "refused: "+lines[0])
	for _, line := range lines[1:] {
		fmt.Fprintln(stderr, line)
	}
	return 2
}
