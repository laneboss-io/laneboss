package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	release "laneboss.io/laneboss/internal/identity"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/service"
)

type dashboardPeer struct {
	*net.UnixConn
	peer wire.SocketPeer
}

func (p *dashboardPeer) Read(raw []byte) (int, error) {
	return wire.ReadPeerBytes(p.UnixConn, p.peer, raw)
}

func dashboardBinding(call Invocation) (api.InstalledBinding, string, error) {
	path := ""
	if call.integrateSocket != nil {
		path = call.integrateSocket.options.BindingFile
	}
	if path == "" {
		path = filepath.Join("/etc/laneboss-v2/bindings", call.Config+".json")
	}
	binding, err := wire.ReadBinding(path, call.Config, release.Version)
	if err != nil {
		return binding, path, err
	}
	digest, err := wire.ArtifactDigest()
	if err != nil {
		return binding, path, err
	}
	if binding.Class != api.EndpointHuman || binding.ArtifactSHA256 != digest {
		return binding, path, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-service", Message: "dashboard entry requires the matched installed human client"}
	}
	return binding, path, nil
}

func dashboardDial(ctx context.Context, binding api.InstalledBinding, bindingFile, suffix string) (*dashboardPeer, error) {
	current, err := wire.ReadBinding(bindingFile, binding.Config, release.Version)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(current, binding) {
		return nil, integrateInputError("dashboard installed binding changed")
	}
	path := binding.Socket + suffix
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || stat.Uid != binding.ServiceUID || stat.Gid != binding.ServiceGID || before.Mode().Perm() != 0660 {
		return nil, integrateInputError("dashboard endpoint identity differs from the protected binding")
	}
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error { return wire.EnableRawCredentials(raw) }}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.Join(integrateInputError("dashboard requires a native Unix endpoint"), conn.Close())
	}
	peer, err := wire.PeerCredentials(socket)
	after, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !os.SameFile(before, after) || peer.UID != binding.MappedServiceUID || peer.GID != binding.MappedServiceGID {
		return nil, errors.Join(integrateInputError("dashboard server peer or socket pin differs"), socket.Close())
	}
	return &dashboardPeer{UnixConn: socket, peer: peer}, nil
}

func dashboardExchange(peer *dashboardPeer, raw []byte) ([]byte, error) {
	if err := peer.SetDeadline(time.Now().Add(35 * time.Second)); err != nil {
		return nil, err
	}
	if err := wire.WriteFrame(peer, raw); err != nil {
		return nil, err
	}
	return wire.ReadFrame(peer)
}

func dashboardWrite(path string, raw []byte) error {
	file, err := os.OpenFile(path+".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(raw)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return integrateInputError("preserve existing dashboard output")
	}
	return os.Rename(path+".pending", path)
}

func dashboardDocument(path string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return dashboardWrite(path, append(raw, '\n'))
}

func runDashboardOpen(ctx context.Context, call Invocation) error {
	flags := integrateFlags(call)
	mode := flags.String("mode", "", "host TLS or retain a native session")
	directory := flags.String("directory", "", "private native session input directory")
	ready := flags.String("ready", "", "new readiness output file")
	origin := flags.String("origin", "", "exact enrolled HTTPS origin")
	listen := flags.String("listen", "127.0.0.1:443", "administrator-owned TLS listen address")
	certificate := flags.String("certificate", "", "administrator TLS certificate")
	key := flags.String("key", "", "administrator TLS private key")
	wait := flags.Duration("wait", 30*time.Minute, "maximum entry lifetime")
	credential := flags.String("credential-id", "", "active human credential for native staging")
	if err := integrateParse(flags, call.Args); err != nil {
		return err
	}
	if !filepath.IsAbs(*ready) || *wait <= 0 || *wait > 30*time.Minute || call.ProofFile != "" || call.SessionProofFile != "" {
		return integrateInputError("dashboard open needs a new absolute readiness file and bounded lifetime")
	}
	binding, bindingFile, err := dashboardBinding(call)
	if err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, *wait)
	defer cancel()
	switch *mode {
	case "session":
		return dashboardSession(runCtx, binding, bindingFile, *directory, *ready, *credential)
	case "host":
		return dashboardHost(runCtx, binding, bindingFile, *origin, *listen, *certificate, *key, *ready)
	}
	return integrateInputError("dashboard open --mode must be host or session")
}

func dashboardSession(ctx context.Context, binding api.InstalledBinding, bindingFile, directory, ready string, credential ...string) error {
	if len(credential) > 1 || len(credential) == 1 && credential[0] != "" && !wire.ValidID(credential[0]) {
		return integrateInputError("dashboard staging requires one active credential identifier")
	}
	physical, err := filepath.EvalSymlinks(directory)
	if err != nil || !filepath.IsAbs(directory) || physical != directory {
		return integrateInputError("dashboard session needs its physical private input directory")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		return integrateInputError("dashboard session directory is not caller-private")
	}
	peer, err := dashboardDial(ctx, binding, bindingFile, ".browser")
	if err != nil {
		return err
	}
	defer peer.Close()
	stop := context.AfterFunc(ctx, func() { _ = peer.Close() })
	defer stop()
	var selected api.ID
	if len(credential) > 0 {
		selected = api.ID(credential[0])
	}
	open, err := json.Marshal(service.DashboardEntryRequest{Protocol: service.DashboardEntryProtocol, Action: "open", CredentialID: selected})
	if err != nil {
		return err
	}
	response, err := dashboardExchange(peer, open)
	if err != nil {
		return err
	}
	var opened service.DashboardEntryReply
	if err := api.DecodeObject(response, &opened); err != nil {
		return err
	}
	if opened.Error != nil {
		return opened.Error
	}
	if err := dashboardWrite(ready, append(response, '\n')); err != nil {
		return err
	}
	seen := make(map[string]bool)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if _, err := os.Lstat(filepath.Join(directory, "close")); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		paths, err := filepath.Glob(filepath.Join(directory, "*.request.json"))
		if err != nil {
			return err
		}
		for _, path := range paths {
			if seen[path] {
				continue
			}
			raw, err := ReadInput(path, api.MaxFrameBytes)
			if err != nil {
				return err
			}
			response, err := dashboardExchange(peer, raw)
			if err != nil {
				return err
			}
			if err := dashboardWrite(strings.TrimSuffix(path, ".request.json")+".response.json", append(response, '\n')); err != nil {
				return err
			}
			seen[path], last = true, time.Now()
			var refused struct {
				Error *api.Error `json:"error"`
			}
			if err := json.Unmarshal(response, &refused); err != nil {
				return err
			}
			if refused.Error != nil {
				return refused.Error
			}
		}
		if time.Since(last) >= 5*time.Second {
			ping, err := json.Marshal(service.DashboardEntryRequest{Protocol: service.DashboardEntryProtocol, Action: "ping"})
			if err != nil {
				return err
			}
			response, err := dashboardExchange(peer, ping)
			if err != nil {
				return err
			}
			var reply service.DashboardEntryReply
			if err := api.DecodeObject(response, &reply); err != nil {
				return err
			}
			if reply.Error != nil {
				return reply.Error
			}
			last = time.Now()
		}
	}
}

func dashboardHost(ctx context.Context, binding api.InstalledBinding, bindingFile, origin, listen, certificate, key, ready string) error {
	target, err := url.Parse(origin)
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		return integrateInputError("dashboard host requires an exact HTTPS origin")
	}
	cert, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", listen, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	if err != nil {
		return err
	}
	defer listener.Close()
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dashboardDial(ctx, binding, bindingFile, ".web")
	}, ResponseHeaderTimeout: 35 * time.Second}
	defer transport.CloseIdleConnections()
	server := &http.Server{Handler: dashboardProxy(transport), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 1 << 16}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	if err := dashboardDocument(ready, map[string]any{"config": binding.Config, "origin": origin, "listening": listener.Addr().String(), "pid": os.Getpid()}); err != nil {
		return err
	}
	err = server.Serve(listener)
	if ctx.Err() != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func dashboardProxy(transport http.RoundTripper) http.Handler {
	return &httputil.ReverseProxy{Transport: transport, FlushInterval: -1, Rewrite: func(r *httputil.ProxyRequest) {
		r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "installed-dashboard", r.In.Host
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-service", Message: "installed dashboard HTTP backend is unavailable"}})
	}}
}

var _ io.ReadWriter = (*dashboardPeer)(nil)
