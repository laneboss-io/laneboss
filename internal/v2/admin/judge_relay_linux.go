//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) judgeProvider(r judgeReg) (string, error) {
	raw, err := readProtected(filepath.Join("/etc/laneboss-v2/service", m.binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		return "", err
	}
	var installation struct {
		Config      string          `json:"config"`
		Judge       api.JudgeConfig `json:"judge"`
		Endpoint    string          `json:"judge_endpoint"`
		Alternative *struct {
			Config   api.JudgeConfig `json:"config"`
			Endpoint string          `json:"endpoint"`
		} `json:"judge_alternative"`
	}
	if json.Unmarshal(raw, &installation) != nil || installation.Config != m.binding.Config {
		return "", failure(api.CodeIntegrity, "judge relay requires its protected installation")
	}
	selected, err := api.ResolveJudgeConfig(r.Execution.Request.Config)
	if err != nil {
		return "", err
	}
	var endpoint string
	primary, err := api.ResolveJudgeConfig(installation.Judge)
	if err == nil && primary == selected {
		endpoint = installation.Endpoint
	}
	if a := installation.Alternative; a != nil {
		alternative, err := api.ResolveJudgeConfig(a.Config)
		if err == nil && alternative == selected {
			endpoint = a.Endpoint
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Scheme != "http" && u.Scheme != "https" || u.Path != "" && u.Path != "/" {
		return "", failure(api.CodePrerequisite, "judge relay has no matching enrolled provider endpoint")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

func (m *leaseManager) judgeRelayMount(w judgeNative) (*nativeMount, error) {
	address, err := m.judgeProvider(w.Reg)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(m.binding.runtimePath(), string(digestBytes([]byte(w.Lease.ID)))[:24]+".sock")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return nil, failure(api.CodeConflict, "judge provider relay is not fresh")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		return nil, err
	}
	end, err := time.Parse(time.RFC3339Nano, string(w.Reg.Execution.Deadline))
	if err != nil {
		listener.Close()
		return nil, err
	}
	if err := listener.SetDeadline(end); err != nil {
		listener.Close()
		return nil, err
	}
	r := &judgeRelay{listener: listener, path: path, done: make(chan struct{})}
	if m.judgeRelays == nil {
		m.judgeRelays = map[api.ID]*judgeRelay{}
	}
	m.judgeRelays[w.Lease.ID] = r
	go func() {
		defer close(r.done)
		peer, err := listener.AcceptUnix()
		if err != nil {
			return
		}
		defer peer.Close()
		raw, err := peer.SyscallConn()
		if err != nil {
			r.err = err
			return
		}
		var cred *unix.Ucred
		var credentialErr error
		if err := raw.Control(func(fd uintptr) {
			cred, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		}); err != nil {
			r.err = err
			return
		}
		if credentialErr != nil || cred == nil || cred.Uid != w.Lease.UID || cred.Gid != w.Lease.GID {
			r.err = failure(api.CodeUnauthenticated, "judge provider relay peer differs from its native allocation")
			return
		}
		ctx, cancel := context.WithDeadline(context.Background(), end)
		defer cancel()
		provider, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err != nil {
			return
		}
		defer provider.Close()
		r.mu.Lock()
		r.peer, r.provider = peer, provider
		r.mu.Unlock()
		peer.SetDeadline(end)
		provider.SetDeadline(end)
		sent := make(chan struct{})
		go func() {
			io.Copy(provider, io.LimitReader(peer, api.MaxJudgeBytes+65536))
			if tcp, ok := provider.(*net.TCPConn); ok {
				tcp.CloseWrite()
			}
			close(sent)
		}()
		io.Copy(peer, io.LimitReader(provider, (1<<20)+65536))
		peer.Close()
		provider.Close()
		<-sent
	}()
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		r.close()
		return nil, err
	}
	return &nativeMount{file: os.NewFile(uintptr(fd), "judge-provider"), target: "/runtime/judge-provider.sock", socket: true}, nil
}
