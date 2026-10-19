package cli

import (
	"context"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dashboard"
)

const (
	dashboardOwner        = "lb-v2-dashboard"
	dashboardDefaultLimit = 100
	dashboardMaxLimit     = 200
	dashboardMaxSafeInt   = (1 << 53) - 1
)

var dashboardMethods = []api.Method{
	"dashboard.tree",
	"dashboard.raw",
	"dashboard.decisions",
	"dashboard.refusals",
	"dashboard.plugins",
	"dashboard.resources",
	"dashboard.lifecycle",
	"dashboard.approvals",
}

func init() {
	for _, method := range dashboardMethods {
		if err := RegisterInputValidator(method, dashboardOwner, dashboard.ValidateQueryJSON); err != nil {
			panic(err)
		}
	}
}

func dashboardInvalid(msg, instead string) *api.Error {
	return &api.Error{
		Code:    api.CodeInvalid,
		Message: msg,
		Instead: instead,
		Owner:   dashboardOwner,
	}
}

func dashboardParseQuery(call Invocation) (api.DashboardQuery, error) {
	q := api.DashboardQuery{Limit: dashboardDefaultLimit}
	seen := make(map[string]bool)

	args := call.Args
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") || arg == "--" {
			return q, dashboardInvalid("unexpected positional argument", "Pass documented dashboard flags or --request FILE.")
		}
		name, val, hasEq := strings.Cut(arg, "=")
		canonName := name
		if canonName == "--lane" || canonName == "--life" {
			canonName = "--life-id"
		}
		if seen[canonName] {
			return q, dashboardInvalid("duplicate flag "+name, "Pass each flag at most once.")
		}
		seen[canonName] = true
		if !hasEq {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "-") {
				return q, dashboardInvalid("missing value for "+name, "Provide a value after "+name+".")
			}
			val = args[i]
		}
		switch canonName {
		case "--life-id":
			q.LifeID = api.ID(val)
		case "--run":
			u, err := strconv.ParseUint(val, 10, 64)
			if err != nil || u == 0 || u > dashboardMaxSafeInt {
				return q, dashboardInvalid("invalid --run value", "Pass a positive integer to --run.")
			}
			q.Run = api.RunNumber(u)
		case "--level":
			lvl, err := strconv.Atoi(val)
			if err != nil || lvl < 3 || lvl > 6 {
				return q, dashboardInvalid("invalid --level value", "Pass 3, 4, 5 or 6 to --level.")
			}
			q.Level = lvl
		case "--driver":
			q.Driver = api.Driver(val)
		case "--since":
			q.Since = api.Timestamp(val)
		case "--until":
			q.Until = api.Timestamp(val)
		case "--cursor":
			q.Cursor = val
		case "--limit":
			lim, err := strconv.Atoi(val)
			if err != nil || lim < 1 || lim > dashboardMaxLimit {
				return q, dashboardInvalid("invalid --limit value", "Pass an integer in 1..200 to --limit.")
			}
			q.Limit = lim
		default:
			return q, dashboardInvalid("unknown flag "+name, "Use --request, --life-id, --run, --level, --driver, --since, --until, --cursor or --limit.")
		}
	}

	if err := dashboard.ValidateQueryInput(q); err != nil {
		return q, err
	}
	return q, nil
}

func dashboardRun(ctx context.Context, call Invocation, method api.Method) error {
	call.Method = method
	query, err := dashboardParseQuery(call)
	if err != nil {
		return err
	}
	return call.Invoke(ctx, query)
}

// runDashboardTree maps file/flag inputs to api.DashboardQuery, then calls dashboard.tree.
func runDashboardTree(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.tree")
}

// runDashboardRaw maps file/flag inputs to api.DashboardQuery, then calls dashboard.raw.
func runDashboardRaw(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.raw")
}

// runDashboardDecisions maps file/flag inputs to api.DashboardQuery, then calls dashboard.decisions.
func runDashboardDecisions(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.decisions")
}

// runDashboardRefusals maps file/flag inputs to api.DashboardQuery, then calls dashboard.refusals.
func runDashboardRefusals(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.refusals")
}

// runDashboardPlugins maps file/flag inputs to api.DashboardQuery, then calls dashboard.plugins.
func runDashboardPlugins(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.plugins")
}

// runDashboardResources maps file/flag inputs to api.DashboardQuery, then calls dashboard.resources.
func runDashboardResources(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.resources")
}

// runDashboardLifecycle maps file/flag inputs to api.DashboardQuery, then calls dashboard.lifecycle.
func runDashboardLifecycle(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.lifecycle")
}

// runDashboardApprovals maps file/flag inputs to api.DashboardQuery, then calls dashboard.approvals.
func runDashboardApprovals(ctx context.Context, call Invocation) error {
	return dashboardRun(ctx, call, "dashboard.approvals")
}
