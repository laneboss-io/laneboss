package box

import (
	"errors"
	"flag"
	"io"
	"math"
	"strings"

	"laneboss.io/laneboss/internal/boxcore"
)

const usage = `usage: laneboss box COMMAND [options]
  launch --provider P --purpose NAME [placement] [--dry-run]
  run --provider P --purpose NAME [placement]
      [--git-sha SHA --repo DIR | --archive FILE]
      (--suite TEXT | --suite-file FILE) [--put LOCAL[:REMOTE]]...
      [--timeout-min N] [--out DIR]
  end [--provider P] --instance ID [--address HOST] [--bound-sec N]
  list [--provider P] [--orphans] [--older-than-min N]
  sweep --provider P --older-than-min N [--delete]
  check [--provider P]

Placement: --vcpu N --mem-gib N --arch x86|arm64|any --families a,b
           --type T --zone Z --root-gb N --idle-min N --hard-min N
           --cost-cap-usd X --lane NAME --owner NAME
Launch and run also accept the purpose as their first positional argument.
Every command accepts --box-config FILE, --config NAME, -h and --help.
Every command except check accepts --format lines|json (default lines).
`

type arguments struct {
	command, config, boxConfig string
	provider, format           string
	request                    boxcore.Request
	families                   string
	dry, orphans, delete       bool
	instance, address          string
	bound, older, timeout      int
	gitSHA, repo, archive      string
	suite, suiteFile, out      string
	puts                       putFlags
	set                        map[string]bool
}

type putFlags []string

// String formats the ordered arguments for flag.Value.
func (p *putFlags) String() string { return strings.Join(*p, ",") }

// Set appends one put argument without changing its position.
func (p *putFlags) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func parse(args []string) (arguments, bool, error) {
	a := arguments{format: "lines", bound: 600}
	if len(args) == 0 {
		return a, false, errors.New("a required argument is missing")
	}
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		return a, true, nil
	}
	a.command = args[0]
	switch a.command {
	case "launch", "run", "end", "list", "sweep", "check":
	default:
		return a, false, errors.New("the subcommand is not accepted")
	}
	fs := flag.NewFlagSet("box", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var help bool
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")
	fs.StringVar(&a.boxConfig, "box-config", "", "")
	fs.StringVar(&a.config, "config", "", "")
	fs.StringVar(&a.provider, "provider", "", "")
	if a.command != "check" {
		fs.StringVar(&a.format, "format", "lines", "")
	}
	if a.command == "launch" || a.command == "run" {
		r := &a.request
		fs.StringVar(&r.Purpose, "purpose", "", "")
		fs.StringVar(&r.Lane, "lane", "", "")
		fs.StringVar(&r.Owner, "owner", "", "")
		fs.IntVar(&r.VCPU, "vcpu", 0, "")
		fs.IntVar(&r.MemGiB, "mem-gib", 0, "")
		fs.StringVar(&r.Arch, "arch", "", "")
		fs.StringVar(&a.families, "families", "", "")
		fs.StringVar(&r.Type, "type", "", "")
		fs.StringVar(&r.Zone, "zone", "", "")
		fs.IntVar(&r.RootGB, "root-gb", 0, "")
		fs.IntVar(&r.IdleMin, "idle-min", 0, "")
		fs.IntVar(&r.HardMin, "hard-min", 0, "")
		fs.Float64Var(&r.CostCapUSD, "cost-cap-usd", 0, "")
	}
	switch a.command {
	case "launch":
		fs.BoolVar(&a.dry, "dry-run", false, "")
	case "run":
		fs.StringVar(&a.gitSHA, "git-sha", "", "")
		fs.StringVar(&a.repo, "repo", "", "")
		fs.StringVar(&a.archive, "archive", "", "")
		fs.StringVar(&a.suite, "suite", "", "")
		fs.StringVar(&a.suiteFile, "suite-file", "", "")
		fs.Var(&a.puts, "put", "")
		fs.IntVar(&a.timeout, "timeout-min", 0, "")
		fs.StringVar(&a.out, "out", "", "")
	case "end":
		fs.StringVar(&a.instance, "instance", "", "")
		fs.StringVar(&a.address, "address", "", "")
		fs.IntVar(&a.bound, "bound-sec", 600, "")
	case "list":
		fs.BoolVar(&a.orphans, "orphans", false, "")
		fs.IntVar(&a.older, "older-than-min", 0, "")
	case "sweep":
		fs.IntVar(&a.older, "older-than-min", 0, "")
		fs.BoolVar(&a.delete, "delete", false, "")
	}
	remaining := args[1:]
	positional := ""
	hasPurpose := false
	if (a.command == "launch" || a.command == "run") &&
		len(remaining) > 0 && !strings.HasPrefix(remaining[0], "-") {
		positional, remaining = remaining[0], remaining[1:]
		hasPurpose = true
	}
	if err := fs.Parse(remaining); err != nil {
		return a, false, errors.New("an argument is not accepted")
	}
	if help {
		return a, true, nil
	}
	a.set = make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { a.set[f.Name] = true })
	if fs.NArg() == 1 && !hasPurpose && !a.set["purpose"] &&
		(a.command == "launch" || a.command == "run") {
		positional, hasPurpose = fs.Arg(0), true
	} else if fs.NArg() != 0 {
		return a, false, errors.New("an argument is not accepted")
	}
	if hasPurpose && a.set["purpose"] {
		return a, false, errors.New("an argument is not accepted")
	}
	if hasPurpose {
		a.request.Purpose = positional
	}
	if a.format != "lines" && a.format != "json" {
		return a, false, errors.New("the format is not accepted")
	}
	if a.command == "launch" || a.command == "run" {
		if a.request.Purpose == "" {
			return a, false, errors.New("a required argument is missing")
		}
		if !boxcore.PlainName(a.request.Purpose) {
			return a, false, errors.New("a name is not accepted")
		}
	}
	if a.command == "run" && a.set["suite"] == a.set["suite-file"] {
		return a, false, errors.New("exactly one suite argument is required")
	}
	for _, name := range []string{"box-config", "config", "provider"} {
		value := map[string]string{
			"box-config": a.boxConfig, "config": a.config, "provider": a.provider,
		}[name]
		if a.set[name] && value == "" {
			return a, false, errors.New("an argument is empty")
		}
	}
	if a.command == "end" && (a.instance == "" || a.bound <= 0) {
		return a, false, errors.New("--instance and a positive --bound-sec are required")
	}
	if a.older < 0 || a.command == "sweep" && !a.set["older-than-min"] {
		return a, false, errors.New("--older-than-min is missing or outside its range")
	}
	return a, false, nil
}

func providerFor(cfg *boxcore.Config, explicit string) (string, error) {
	p := explicit
	if p == "" {
		p = cfg.Defaults.Provider
	}
	if p == "" && (cfg.AWS != nil) != (cfg.GCP != nil) {
		if cfg.AWS != nil {
			p = "aws"
		} else {
			p = "gcp"
		}
	}
	if !boxcore.PlainName(p) ||
		!(p == "aws" && cfg.AWS != nil || p == "gcp" && cfg.GCP != nil) {
		return "", errors.New("a configured provider is required")
	}
	return p, nil
}

func (a *arguments) placement(cfg *boxcore.Config, getenv func(string) string) error {
	r, d := &a.request, cfg.Defaults
	r.Provider = a.provider
	if !a.set["vcpu"] {
		r.VCPU = d.VCPU
	}
	if !a.set["mem-gib"] {
		r.MemGiB = d.MemGiB
	}
	if !a.set["arch"] {
		r.Arch = d.Arch
	}
	if !a.set["root-gb"] {
		r.RootGB = d.RootGB
	}
	if !a.set["idle-min"] {
		r.IdleMin = d.IdleMin
	}
	if !a.set["hard-min"] {
		r.HardMin = d.HardMin
	}
	if !a.set["cost-cap-usd"] {
		r.CostCapUSD = d.CostCapUSD
	}
	if !a.set["lane"] {
		r.Lane = getenv("LANEBOSS_BOX_LANE")
		if r.Lane == "" {
			r.Lane = r.Purpose
		}
	}
	r.OwnerBasis = "flag"
	if !a.set["owner"] {
		r.Owner, r.OwnerBasis = getenv("LANEBOSS_BOX_OWNER"), "env"
		if r.Owner == "" {
			r.Owner, r.OwnerBasis = "unknown", "unknown"
		}
	}
	if r.Purpose == "" {
		return errors.New("a required argument is missing")
	}
	for _, name := range []string{r.Provider, r.Purpose, r.Lane, r.Owner} {
		if !boxcore.PlainName(name) {
			return errors.New("a name is not accepted")
		}
	}
	if (r.Type == "") != (r.Zone == "") ||
		a.set["type"] && r.Type == "" || a.set["zone"] && r.Zone == "" {
		return errors.New("--type and --zone are required together")
	}
	if r.Arch != "x86" && r.Arch != "arm64" && r.Arch != "any" {
		return errors.New("the architecture is not accepted")
	}
	switch r.VCPU {
	case 2, 4, 8, 16, 32, 48, 64:
	default:
		return errors.New("--vcpu is outside its range")
	}
	if r.MemGiB < 0 || r.HardMin < 10 || r.HardMin > 10080 ||
		r.IdleMin < 1 || r.IdleMin > 1440 || r.RootGB < 8 || r.RootGB > 2000 ||
		math.IsNaN(r.CostCapUSD) || math.IsInf(r.CostCapUSD, 0) || r.CostCapUSD <= 0 {
		return errors.New("a placement number is outside its range")
	}
	if a.families != "" {
		for _, family := range strings.Split(a.families, ",") {
			family = strings.TrimSpace(family)
			if family == "" {
				return errors.New("a family is empty")
			}
			r.Families = append(r.Families, family)
		}
	}
	return nil
}
