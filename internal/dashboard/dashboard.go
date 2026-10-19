// Package dashboard serves authenticated local views and guarded human messages.
package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"laneboss.io/laneboss/internal/caller"
	"laneboss.io/laneboss/internal/config"
	"laneboss.io/laneboss/internal/eventstore"
	"laneboss.io/laneboss/internal/faults"
	"laneboss.io/laneboss/internal/judge"
	"laneboss.io/laneboss/internal/ledger"
	"laneboss.io/laneboss/internal/plugin"
	"laneboss.io/laneboss/internal/refusal"
	"laneboss.io/laneboss/internal/toolrecord"
)

const usage = "usage: laneboss dashboard --config NAME [--port N] [--bind 127.0.0.1]"

type options struct {
	config, bind string
	port         int
	help         bool
}

func parse(args []string) (options, error) {
	o := options{bind: "127.0.0.1"}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			o.help = true
			continue
		}
		name, value, inline := strings.Cut(args[i], "=")
		if name != "--config" && name != "--port" && name != "--bind" || seen[name] {
			return o, errors.New("the command line is not accepted")
		}
		seen[name] = true
		if !inline {
			i++
			if i >= len(args) || strings.HasPrefix(args[i], "--") {
				return o, errors.New("an option value is required")
			}
			value = args[i]
		}
		switch name {
		case "--config":
			if err := config.CheckName(value); err != nil {
				return o, err
			}
			o.config = value
		case "--bind":
			o.bind = value
		case "--port":
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 65535 {
				return o, errors.New("--port must be an integer from 0 to 65535")
			}
			o.port = n
		}
	}
	if o.help {
		return o, nil
	}
	if o.config == "" {
		return o, errors.New("--config is required")
	}
	if o.bind != "127.0.0.1" && faults.Get("dashboard-any-bind").Point == "" {
		return o, errors.New("--bind must be 127.0.0.1; the dashboard is loopback-only")
	}
	return o, nil
}

// Run is dispatched by cmd/laneboss through the unified command router.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parse(args)
	if err != nil {
		fmt.Fprintln(stderr, usage)
		fmt.Fprintln(stderr, "refused: "+err.Error())
		return 2
	}
	if o.help {
		fmt.Fprintln(stdout, usage+"\nServe an authenticated local dashboard. Port 0 selects a free local port.")
		return 0
	}
	// Validate configuration and isolation before opening a listening socket.
	c, err := config.Load(o.config)
	if err != nil {
		fmt.Fprintln(stderr, "refused: dashboard configuration could not be loaded")
		return 2
	}
	// Only the human starts the dashboard: a lane never holds its token.
	principal, refused := startingHuman(c)
	if refused != "" {
		fmt.Fprintln(stderr, refused)
		return 2
	}
	binding, err := eventstore.Bind(o.config)
	if err != nil {
		fmt.Fprintln(stderr, "refused: dashboard configuration isolation could not be checked")
		return 2
	}
	token, err := newToken()
	if err != nil {
		fmt.Fprintln(stderr, "cannot create the dashboard token")
		return 70
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	h := &handler{name: o.config, token: token, principal: principal}
	// Prepare the same verified snapshot and graph index used by requests
	// before advertising readiness. Startup work is reported separately.
	if _, _, _, err = h.snapshot(ctx, binding); err != nil {
		if ctx.Err() != nil {
			return 1
		}
		fmt.Fprintln(stderr, "dashboard data is unavailable; affected requests will report a read error")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(o.bind, strconv.Itoa(o.port)))
	if err != nil {
		fmt.Fprintln(stderr, "refused: cannot open the dashboard's local port")
		return 2
	}
	defer listener.Close()
	h.host = listener.Addr().String()
	address := "http://" + listener.Addr().String() + "/#t=" + token
	if _, err = fmt.Fprintln(stdout, address); err != nil {
		return 1
	}
	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0),
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if server.Shutdown(shutdown) != nil {
			server.Close()
		}
	}()
	err = server.Serve(listener)
	cancel()
	<-stopped
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(stderr, "dashboard server stopped unexpectedly")
		return 1
	}
	return 0
}

type handler struct {
	name, host, token string
	principal         caller.Principal
	cache             displayCache
	usage             eventstore.UsageCache
}

// screen is also a tagged fault point: release builds cannot disable it.
func screen(value any) any {
	if faults.Get("dashboard-no-screen").Point != "" {
		return value
	}
	return eventstore.ScreenValue(value)
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	data, err := json.Marshal(screen(value))
	if err != nil {
		status, data = http.StatusInternalServerError, []byte(`{"error":"dashboard output could not be encoded"}`)
	}
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Context().Err() != nil {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	if r.Host != h.host {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/" {
		if r.URL.RawQuery != "" {
			reply(w, 400, object{"error": "query options are not accepted"})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, experiencePage())
		return
	}
	if !h.authenticated(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet {
		h.cookieFaultIssue(w)
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/messages/send" {
		if !h.validOrigin(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.send(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/refusals/report" {
		if !h.validOrigin(r) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.reportRefusal(w, r)
		return
	}
	// Every other method is refused before loading configuration or state.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		reply(w, http.StatusMethodNotAllowed, object{"error": "only GET is allowed here"})
		return
	}
	selection := eventOptions{limit: 100}
	query, err := parseQuery(r, &selection)
	if err != nil || !query {
		reply(w, http.StatusBadRequest, map[string]any{"error": "query options are not accepted"})
		return
	}
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, experiencePage())
		return
	}
	if r.URL.Path == "/api/messages/send" || r.URL.Path == "/api/refusals/report" {
		w.Header().Set("Allow", "POST")
		reply(w, http.StatusMethodNotAllowed, object{"error": "only POST is allowed here"})
		return
	}
	if r.URL.Path != "/api/org" && r.URL.Path != "/api/lanes" && r.URL.Path != "/api/events" && r.URL.Path != "/api/refusals" && r.URL.Path != "/api/board" && r.URL.Path != "/api/health" && r.URL.Path != "/api/judge" && r.URL.Path != "/api/plugins" && r.URL.Path != "/api/messages" && r.URL.Path != "/api/logs" && r.URL.Path != "/api/analytics" && r.URL.Path != "/api/decisions" && r.URL.Path != "/api/graph" && r.URL.Path != "/api/now" && r.URL.Path != "/api/ledger" && r.URL.Path != "/api/proposals" && r.URL.Path != "/api/tools" {
		reply(w, http.StatusNotFound, map[string]any{"error": "endpoint not found"})
		return
	}
	if r.URL.Path == "/api/ledger" {
		selection := ledger.Selection{Instance: r.URL.Query().Get("instance"), Lane: r.URL.Query().Get("lane"), Since: r.URL.Query().Get("since")}
		if _, err := selection.Validate(); err != nil {
			reply(w, 400, object{"error": "invalid ledger selection"})
			return
		}
		value, err := ledger.ReadContext(r.Context(), h.name, selection, &h.usage)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			reply(w, 503, object{"error": "ledger records could not be read"})
			return
		}
		reply(w, 200, value)
		return
	}
	if r.URL.Path == "/api/proposals" || r.URL.Path == "/api/tools" {
		binding, err := eventstore.Bind(h.name)
		if err != nil {
			reply(w, 503, object{"error": "records unavailable"})
			return
		}
		_, events, _, err := h.snapshot(r.Context(), binding)
		if err != nil {
			reply(w, 503, object{"error": "records unavailable"})
			return
		}
		if r.URL.Path == "/api/proposals" {
			reply(w, 200, refusal.Proposals(events))
		} else {
			reply(w, 200, toolrecord.Rows(events))
		}
		return
	}
	c, err := config.Load(h.name)
	if err != nil {
		reply(w, http.StatusServiceUnavailable, map[string]any{"error": "configuration could not be read"})
		return
	}
	var value any
	switch r.URL.Path {
	case "/api/board":
		value, err = c.ReadBoard(time.Now())
	case "/api/judge":
		if r.URL.Query().Get("view") == "control" {
			value, err = judgmentView(r.Context(), c.Name)
		} else {
			value, err = judge.ReadDecisionsContext(r.Context(), c.Name)
		}
	case "/api/plugins":
		value, err = plugin.Inventory()
	default:
		var binding *eventstore.Configuration
		binding, err = eventstore.Bind(h.name)
		if err == nil {
			var lanes, events []eventstore.Object
			var graph *graphInputs
			began := time.Now()
			lanes, events, graph, err = h.snapshot(r.Context(), binding)
			snapshotMillis := float64(time.Since(began).Microseconds()) / 1000
			if err == nil {
				switch r.URL.Path {
				case "/api/org":
					value, err = orgView(c, events)
				case "/api/graph":
					began = time.Now()
					value, err = graph.view(r.Context(), began)
					w.Header().Set("Server-Timing", fmt.Sprintf("snapshot;dur=%.3f, graph;dur=%.3f, last_verify;dur=%.3f, last_index;dur=%.3f", snapshotMillis, float64(time.Since(began).Microseconds())/1000, graph.verifyMillis, graph.buildMillis))
				case "/api/now":
					value, err = nowView(r.Context(), c, binding, lanes, events, time.Now(), &h.usage)
				case "/api/lanes":
					value = laneView(lanes, events, time.Now())
				case "/api/events":
					value, err = eventBoard(c, events, selection, time.Now())
				case "/api/messages":
					value, err = messageView(r.Context(), c, binding, events)
				case "/api/logs":
					h.logs(w, r, c, binding, lanes, events)
					return
				case "/api/analytics":
					window := r.URL.Query().Get("window")
					if window == "" {
						window = "24h"
					}
					idle := 15
					if raw := r.URL.Query().Get("idle_minutes"); raw != "" {
						idle, err = strconv.Atoi(raw)
					}
					if err != nil || idle < 1 || idle > 10080 || (window != "1h" && window != "24h" && window != "7d") {
						reply(w, 400, object{"error": "invalid analytics window or idle threshold"})
						return
					}
					value, err = analytics(r.Context(), binding, lanes, events, window, idle, time.Now(), &h.usage)
				case "/api/decisions":
					value, err = decisionView(binding, r.URL.Query().Get("q"), lanes)
				case "/api/refusals":
					if r.URL.Query().Get("view") == "groups" {
						value, err = refusalGroups(h.name, events)
					} else {
						value = refusalView(events)
					}
				case "/api/health":
					value, err = healthView(c, events)
				}
			}
		}
	}
	if r.Context().Err() != nil {
		return
	}
	if err != nil {
		reply(w, http.StatusServiceUnavailable, map[string]any{"error": "dashboard data could not be read; check the configuration and state with the CLI"})
		return
	}
	reply(w, http.StatusOK, value)
}

type eventOptions struct {
	limit, level  int
	lane, kind    string
	runner, model string
	account, rule string
	outcome       string
	board         bool
	since, until  time.Time
}

func parseQuery(r *http.Request, selection *eventOptions) (bool, error) {
	values, err := urlQuery(r.URL.RawQuery)
	if err != nil {
		return false, err
	}
	for name, list := range values {
		if r.URL.Path == "/api/judge" {
			if name != "view" || len(list) != 1 || list[0] != "control" {
				return false, nil
			}
			continue
		}
		if r.URL.Path == "/api/refusals" {
			if name != "view" || len(list) != 1 || list[0] != "groups" {
				return false, nil
			}
			continue
		}
		if r.URL.Path == "/api/ledger" {
			if len(list) != 1 || len(list[0]) > 128 || name != "instance" && name != "lane" && name != "since" {
				return false, nil
			}
			continue
		}
		if r.URL.Path == "/api/analytics" || r.URL.Path == "/api/decisions" {
			if len(list) != 1 || len(list[0]) > 512 {
				return false, nil
			}
			if r.URL.Path == "/api/analytics" && (name == "window" || name == "idle_minutes") || r.URL.Path == "/api/decisions" && name == "q" {
				continue
			}
			return false, nil
		}
		if r.URL.Path == "/api/logs" {
			if (name != "lane" && name != "tail") || len(list) != 1 {
				return false, nil
			}
			continue
		}
		if r.URL.Path != "/api/events" || len(list) != 1 {
			return false, nil
		}
		value := list[0]
		if len(value) > 128 || strings.ContainsAny(value, "\r\n\x00") {
			return false, nil
		}
		switch name {
		case "limit":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 1000 {
				return false, nil
			}
			selection.limit = n
		case "lane":
			selection.lane = value
		case "kind":
			selection.kind = value
		case "runner":
			selection.runner = value
		case "model":
			selection.model = value
		case "account":
			selection.account = value
		case "rule":
			selection.rule = value
		case "outcome":
			selection.outcome = value
		case "level":
			n, err := strconv.Atoi(value)
			if err != nil || n < 3 || n > 6 {
				return false, nil
			}
			selection.level = n
		case "view":
			if value != "board" {
				return false, nil
			}
			selection.board = true
		case "since", "until":
			at, err := time.Parse(time.RFC3339Nano, value)
			if err != nil {
				return false, nil
			}
			if name == "since" {
				selection.since = at
			} else {
				selection.until = at
			}
		default:
			return false, nil
		}
	}
	return true, nil
}
