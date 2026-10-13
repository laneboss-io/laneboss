package decisionsrv

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/decisions/jsonout"
)

const maxBody = 1 << 20

func socketPathLimit() int {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		return 104
	}
	return 108
}
func privateDirectory(path string, create bool) error {
	info, e := os.Stat(path)
	if os.IsNotExist(e) {
		parent, e := os.Stat(filepath.Dir(path))
		if e != nil || !parent.IsDir() {
			return invalid("the directory " + path + " for the socket does not exist, and neither does the one above it")
		}
		if !create {
			return nil
		}
		if e = os.Mkdir(path, 0700); e != nil {
			return invalid("cannot make the directory " + path + " for the socket")
		}
		return os.Chmod(path, 0700)
	}
	if e != nil {
		return invalid("cannot read the directory " + path + " for the socket")
	}
	if !info.IsDir() {
		return invalid(path + " is not a directory")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0077 != 0 {
		return invalid("the directory " + path + " for the socket must be yours alone (mode 700) and is not: change it with chmod 700, or give the socket a directory of its own")
	}
	return nil
}
func claimSocket(path string, removeStale bool) error {
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return invalid("cannot inspect socket path")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return invalid(path + " exists and is not a socket, and is not replaced")
	}
	connection, e := net.DialTimeout("unix", path, 5*time.Second)
	if e == nil {
		connection.Close()
		return invalid("a server is already listening on " + path)
	}
	if errors.Is(e, syscall.ECONNREFUSED) || os.IsNotExist(e) {
		if !removeStale {
			return nil
		}
		current, e := os.Lstat(path)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil || !os.SameFile(info, current) {
			return invalid("socket path changed during preflight")
		}
		if e = os.Remove(path); e != nil && !os.IsNotExist(e) {
			return invalid("cannot remove stale socket")
		}
		return nil
	}
	return invalid("cannot tell whether a server listens on " + path)
}
func socketPreflight(path string) error {
	if len(path) > socketPathLimit() {
		return invalid(fmt.Sprintf("the socket path is %d bytes long and this system allows at most %d (a limit of Unix sockets); give --socket a shorter path in a directory of your own, for example under $TMPDIR on macOS or $XDG_RUNTIME_DIR on Linux", len(path), socketPathLimit()))
	}
	if e := privateDirectory(filepath.Dir(path), false); e != nil {
		return e
	}
	return claimSocket(path, false)
}

type unixServer struct {
	resident    *resident
	modeAtBind  os.FileMode
	mu          sync.Mutex
	active      int
	last        time.Time
	connections map[net.Conn]bool
	workers     sync.WaitGroup
}

func (s *unixServer) begin() { s.mu.Lock(); s.active++; s.mu.Unlock() }
func (s *unixServer) end()   { s.mu.Lock(); s.active--; s.last = time.Now(); s.mu.Unlock() }
func (s *unixServer) idle(limit time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active == 0 && time.Since(s.last) >= limit
}
func (s *unixServer) close() {
	s.mu.Lock()
	for conn := range s.connections {
		conn.Close()
	}
	s.mu.Unlock()
	s.workers.Wait()
}

func serve(dbPath, socketPath, config string, minutes float64, stdout, stderr io.Writer) error {
	path, e := filepath.Abs(socketPath)
	if e != nil {
		return invalid("unreadable socket path")
	}
	if e = socketPreflight(path); e != nil {
		return e
	}
	r, e := newResident(dbPath, config)
	if e != nil {
		return e
	}
	defer r.close()
	snapshot, e := r.current(context.Background())
	if e != nil {
		return e
	}
	damage := snapshot.damage
	snapshot.release()
	if damage != nil {
		return damage
	}
	if e = privateDirectory(filepath.Dir(path), true); e != nil {
		return e
	}
	if e = claimSocket(path, true); e != nil {
		return e
	}
	// Bind under the restrictive mask, before the socket exists. The server has no
	// other goroutine creating filesystem objects during this short interval.
	mask := syscall.Umask(0177)
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	var made os.FileInfo
	if e == nil {
		made, e = os.Lstat(path)
	}
	syscall.Umask(mask)
	if e != nil {
		if listener != nil {
			listener.Close()
		}
		return invalid("cannot listen on " + path)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	defer func() {
		if current, e := os.Lstat(path); e == nil && os.SameFile(made, current) {
			os.Remove(path)
		}
	}()
	if made.Mode().Perm() != 0600 {
		return invalid("socket was not private at bind")
	}
	s := &unixServer{resident: r, modeAtBind: made.Mode().Perm(), last: time.Now(), connections: map[net.Conn]bool{}}
	defer s.close()
	stopped := make(chan os.Signal, 1)
	numbers := []os.Signal{syscall.SIGTERM}
	for _, n := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP} {
		if !signal.Ignored(n) {
			numbers = append(numbers, n)
		}
	}
	signal.Notify(stopped, numbers...)
	defer signal.Stop(stopped)
	ready, e := jsonout.Line(object{"ok": true, "pid": os.Getpid(), "socket": path})
	if e != nil {
		return invalid(e.Error())
	}
	if _, e = stdout.Write(ready); e != nil {
		return invalid("cannot write ready line")
	}
	limit := time.Duration(minutes * 60 * float64(time.Second))
	if minutes > float64(mathMaxDuration)/float64(time.Minute) {
		limit = mathMaxDuration
	}
	for {
		select {
		case <-stopped:
			return nil
		default:
		}
		if s.idle(limit) {
			return nil
		}
		listener.SetDeadline(time.Now().Add(100 * time.Millisecond))
		conn, e := listener.AcceptUnix()
		if e != nil {
			if n, ok := e.(net.Error); ok && n.Timeout() {
				continue
			}
			return invalid("cannot accept socket connection")
		}
		s.mu.Lock()
		s.connections[conn] = true
		s.mu.Unlock()
		s.workers.Add(1)
		go s.connection(conn)
	}
}

const mathMaxDuration time.Duration = 1<<63 - 1

type wireRequest struct {
	method, target string
	headers        textproto.MIMEHeader
	close          bool
}

func readWireLine(reader *bufio.Reader, budget *int) (string, error) {
	var b strings.Builder
	for {
		part, prefix, e := reader.ReadLine()
		if e != nil {
			return "", e
		}
		*budget -= len(part) + 2
		if *budget < 0 {
			return "", fmt.Errorf("HTTP header exceeds limit")
		}
		b.Write(part)
		if !prefix {
			return b.String(), nil
		}
	}
}
func readWireRequest(reader *bufio.Reader) (wireRequest, error) {
	budget := 64 << 10
	line, e := readWireLine(reader, &budget)
	if e != nil {
		return wireRequest{}, e
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || (parts[2] != "HTTP/1.1" && parts[2] != "HTTP/1.0") {
		return wireRequest{}, fmt.Errorf("invalid request line")
	}
	req := wireRequest{method: parts[0], target: parts[1], headers: textproto.MIMEHeader{}, close: parts[2] == "HTTP/1.0"}
	for {
		line, e := readWireLine(reader, &budget)
		if e != nil {
			return req, e
		}
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.TrimSpace(key) != key {
			return req, fmt.Errorf("invalid HTTP header")
		}
		for _, r := range key {
			if !(r > 32 && r < 127) || strings.ContainsRune("()<>@,;:\\[]?={}\"", r) {
				return req, fmt.Errorf("invalid HTTP header")
			}
		}
		req.headers.Add(key, strings.TrimSpace(value))
	}
	if strings.EqualFold(req.headers.Get("Connection"), "close") {
		req.close = true
	}
	return req, nil
}
func writeReply(conn net.Conn, status int, body []byte, kind string, close bool, code int, allow bool) error {
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	var header strings.Builder
	fmt.Fprintf(&header, "HTTP/1.1 %d %s\r\nServer: laneboss-decisions\r\nContent-Type: %s\r\nContent-Length: %d\r\n", status, http.StatusText(status), kind, len(body))
	if close {
		header.WriteString("Connection: close\r\n")
	}
	if code != 0 {
		fmt.Fprintf(&header, "X-Exit-Code: %d\r\n", code)
	}
	if allow {
		header.WriteString("Allow: GET, POST\r\n")
	}
	header.WriteString("\r\n")
	if _, e := io.WriteString(conn, header.String()); e != nil {
		return e
	}
	_, e := conn.Write(body)
	return e
}
func parseForm(text string) ([]pair, error) {
	if !utf8.ValidString(text) {
		return nil, invalid("unreadable path or unsupported text")
	}
	pairs := []pair{}
	for _, part := range strings.Split(text, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		n, e := url.QueryUnescape(name)
		if e != nil {
			return nil, invalid("invalid form encoding")
		}
		v, e := url.QueryUnescape(value)
		if e != nil || !utf8.ValidString(n) || !utf8.ValidString(v) {
			return nil, invalid("unreadable path or unsupported text")
		}
		pairs = append(pairs, pair{n, v})
	}
	return pairs, nil
}
func (s *unixServer) connection(conn net.Conn) {
	defer s.workers.Done()
	defer conn.Close()
	defer func() { s.mu.Lock(); delete(s.connections, conn); s.mu.Unlock() }()
	reader := bufio.NewReader(conn)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		req, e := readWireRequest(reader)
		if e != nil {
			return
		}
		s.begin()
		close := s.handle(conn, reader, req)
		s.end()
		if close {
			return
		}
	}
}
func (s *unixServer) handle(conn net.Conn, reader *bufio.Reader, req wireRequest) bool {
	close := req.close
	unread := req.headers.Get("Transfer-Encoding") != "" || (strings.TrimSpace(req.headers.Get("Content-Length")) != "" && strings.TrimSpace(req.headers.Get("Content-Length")) != "0")
	textReply := func(status int, message string, code int, allow bool) bool {
		if writeReply(conn, status, []byte(message+"\n"), "text/plain; charset=utf-8", close, code, allow) != nil {
			return true
		}
		return close
	}
	refuse := func(e error) bool {
		code := errorCode(e)
		status := map[int]int{2: 400, 3: 500, 4: 502, 5: 503, 6: 500, 7: 500}[code]
		if status == 0 {
			status = 500
		}
		return textReply(status, e.Error(), code, false)
	}
	if req.method != "GET" && req.method != "POST" {
		close = close || unread
		return textReply(405, "method not allowed", 0, true)
	}
	target, e := url.ParseRequestURI(req.target)
	if e != nil {
		close = true
		return refuse(invalid("invalid request target"))
	}
	if target.Path == "/status" && req.method == "GET" {
		close = close || unread
		status := s.resident.status()
		status["socket_mode_at_bind"] = int(s.modeAtBind)
		body, e := jsonout.Line(status)
		if e != nil {
			return refuse(invalid(e.Error()))
		}
		return writeReply(conn, 200, body, "application/json", close, 0, false) != nil || close
	}
	if target.Path == "/status" {
		close = close || unread
		return textReply(405, "method not allowed", 0, true)
	}
	if target.Path != "/search" {
		close = close || unread
		return textReply(404, "not found", 0, false)
	}
	var sent []byte
	if req.method == "POST" {
		if req.headers.Get("Transfer-Encoding") != "" {
			close = true
			return refuse(invalid("a request body needs a Content-Length"))
		}
		lengths := req.headers.Values("Content-Length")
		if len(lengths) > 1 {
			close = true
			return refuse(invalid("the Content-Length is ambiguous"))
		}
		length := int64(0)
		if req.headers.Get("Content-Length") != "" {
			length, e = strconv.ParseInt(req.headers.Get("Content-Length"), 10, 64)
			if e != nil {
				close = true
				return refuse(invalid("the Content-Length is not a number"))
			}
		}
		if length < 0 || length > maxBody {
			close = true
			return refuse(invalid(fmt.Sprintf("a request body is at most %d bytes", maxBody)))
		}
		sent = make([]byte, int(length))
		if _, e = io.ReadFull(reader, sent); e != nil {
			return true
		}
	} else {
		close = close || unread
	}
	pairs, e := parseForm(target.RawQuery)
	if e != nil {
		return refuse(e)
	}
	if req.method == "POST" {
		kind := strings.ToLower(strings.TrimSpace(strings.Split(req.headers.Get("Content-Type"), ";")[0]))
		if kind != "" && kind != "application/x-www-form-urlencoded" {
			return refuse(invalid("a request body is a form: application/x-www-form-urlencoded"))
		}
		form, e := parseForm(string(sent))
		if e != nil {
			return refuse(e)
		}
		pairs = append(pairs, form...)
	}
	a, e := parseSearch(pairs)
	if e != nil {
		return refuse(e)
	}
	body, e := s.resident.answer(context.Background(), a)
	if e != nil {
		return refuse(e)
	}
	return writeReply(conn, 200, body, "application/json", close, 0, false) != nil || close
}
