//go:build linux

package admin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// componentPort is the name of the method that the private component binds to
// one helper port the broker calls: the method value under port in
// assembly/credowners_linux.go's methods map.
func componentPort(t *testing.T, port string) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "assembly", "credowners_linux.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	bound := ""
	ast.Inspect(file, func(node ast.Node) bool {
		entry, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, isKey := entry.Key.(*ast.BasicLit)
		value, isMethod := entry.Value.(*ast.SelectorExpr)
		if isKey && isMethod && key.Value == strconv.Quote(port) {
			bound = value.Sel.Name
		}
		return true
	})
	return bound
}

// componentRuntimePort is the stallHelper method that the private component
// binds to the "helper.ResolveRuntime" port the broker's transfer calls.
func componentRuntimePort(t *testing.T, helper *stallHelper) func(context.Context, api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	t.Helper()
	bound := componentPort(t, "helper.ResolveRuntime")
	method := reflect.ValueOf(helper).MethodByName(bound)
	if bound == "" || !method.IsValid() {
		t.Fatalf("the component's helper.ResolveRuntime port binds no helper client method (%q)", bound)
	}
	port, ok := method.Interface().(func(context.Context, api.PreparedSpecHandoff) (api.ResolvedRuntime, error))
	if !ok {
		t.Fatalf("the component's helper.ResolveRuntime port %s has another signature", bound)
	}
	return port
}

// componentGatePort sends, over stallHelper's endpoints, the helper methods
// that the Service method bound to the component's "helper.ObserveGate" port
// sends (serviceCalls reads them from that method's own source).
func componentGatePort(t *testing.T, helper *stallHelper) func(context.Context) error {
	t.Helper()
	bound := componentPort(t, "helper.ObserveGate")
	method, ok := reflect.TypeFor[*Service]().MethodByName(bound)
	if bound == "" || !ok || method.Type != reflect.TypeFor[func(*Service, context.Context, api.HelperObserveRequest) (api.ProcessObservation, error)]() {
		t.Fatalf("the component's helper.ObserveGate port binds no Service gate observation (%q)", bound)
	}
	calls := serviceCalls(t, bound)
	return func(ctx context.Context) error {
		for _, call := range calls {
			if err := helper.send(ctx, call); err != nil {
				return err
			}
		}
		return nil
	}
}

// serviceCalls is the helper methods that the Service method name sends: the
// method literals of its s.call calls in this package's Linux source.
func serviceCalls(t *testing.T, name string) []string {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	definitions := 0
	for _, path := range paths {
		if match, err := build.Default.MatchFile(".", path); err != nil || !match || strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn := serviceMethod(decl, name)
			if fn == nil {
				continue
			}
			definitions++
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) < 2 {
					return true
				}
				if selector, ok := call.Fun.(*ast.SelectorExpr); !ok || selector.Sel.Name != "call" {
					return true
				}
				literal, ok := call.Args[1].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("Service.%s calls the helper with a method that is not a literal", name)
				}
				method, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatal(err)
				}
				calls = append(calls, method)
				return true
			})
		}
	}
	if definitions != 1 || len(calls) == 0 {
		t.Fatalf("Service.%s: %d definitions sending %q", name, definitions, calls)
	}
	return calls
}

func serviceMethod(decl ast.Decl, name string) *ast.FuncDecl {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Name.Name != name || fn.Recv == nil || len(fn.Recv.List) != 1 || fn.Body == nil {
		return nil
	}
	if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
		if receiver, ok := star.X.(*ast.Ident); ok && receiver.Name == "Service" {
			return fn
		}
	}
	return nil
}

// stallHelper is the service's helper client over real Unix sockets. Each helper
// method crosses the endpoint that credentialMetadataMethod selects, as
// Service.call does; each port sends the requests its Service method sends.
type stallHelper struct{ ordinary, metadata string }

func newStallHelper(t *testing.T) *stallHelper {
	dir := t.TempDir()
	return &stallHelper{ordinary: filepath.Join(dir, "helper.sock"), metadata: filepath.Join(dir, "metadata.sock")}
}

func (h *stallHelper) send(ctx context.Context, method string) error {
	path := h.ordinary
	if credentialMetadataMethod(method) {
		path = h.metadata
	}
	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return err
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { connection.SetDeadline(time.Now()) })
	defer stop()
	if _, err := connection.Write([]byte(method + "\n")); err != nil {
		return err
	}
	reply, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return err
	}
	if reply != "ok\n" {
		return errors.New(method + ": " + strings.TrimSpace(reply))
	}
	return nil
}

// ResolveRuntime sends what Service.ResolveRuntime sends (runtime_resolve.go).
func (h *stallHelper) ResolveRuntime(ctx context.Context, _ api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	for _, method := range []string{"resolve_storage", "register_spec", "probe", "resolve_runtime"} {
		if err := h.send(ctx, method); err != nil {
			return api.ResolvedRuntime{}, err
		}
	}
	return api.ResolvedRuntime{}, nil
}

// ResolveCredentialRuntime sends what Service.ResolveCredentialRuntime sends.
func (h *stallHelper) ResolveCredentialRuntime(ctx context.Context, _ api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	return api.ResolvedRuntime{}, h.send(ctx, "resolve_runtime")
}

// serveStall serves one helper stream with the helper's own locks: the ordinary
// listener under lockHelperOperation(false), a metadata stream under (true) and
// only for metadata methods, as serveHelperRequest does. The pending ordinary
// call waits on the broker under its operation context.
func serveStall(ctx context.Context, connection *net.UnixConn, manager *leaseManager, metadata bool, pending string, wait func(context.Context) error, beside func()) {
	defer connection.Close()
	line, err := bufio.NewReader(connection).ReadString('\n')
	if err != nil {
		return
	}
	method := strings.TrimSuffix(line, "\n")
	reply := "ok\n"
	if metadata && !credentialMetadataMethod(method) {
		reply = "refused\n"
	} else {
		operationCtx, unlock := manager.lockHelperOperation(ctx, metadata)
		if method == pending {
			if err := wait(operationCtx); err != nil {
				reply = "refused " + err.Error() + "\n"
			}
		} else if metadata {
			beside()
		}
		unlock()
	}
	connection.Write([]byte(reply))
}

// stallCallback runs the helper's ordinary pending call (prepare or release),
// which holds the serialized listener and helperMu and waits on the broker's
// exchange (transfer or refresh) over a real credential channel, lending only
// operationMu. The broker calls one of the private component's helper ports
// back. That callback must be one metadata read served while the pending call
// waits; on the ordinary listener it waits behind that call until the call's
// own recv deadline (2 s here, 10 s installed) expires.
func stallCallback(t *testing.T, helper *stallHelper, pending, exchange string, callback func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ordinary, err := net.ListenUnix("unix", &net.UnixAddr{Name: helper.ordinary, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := net.ListenUnix("unix", &net.UnixAddr{Name: helper.metadata, Net: "unix"})
	if err != nil {
		ordinary.Close()
		t.Fatal(err)
	}
	manager := &leaseManager{}
	client, server := nativePair(t)
	peer, serverPeer := nativePeer(t, client), nativePeer(t, server)
	channel := &credentialChannel{connection: client, peer: peer, operationMu: &manager.operationMu}
	waited := make(chan error, 1)
	wait := func(operationCtx context.Context) error {
		request := helperRequest{Protocol: credentialProtocol, Revision: api.ContractRevision, Config: "admin-case", Generation: 1, ArtifactSHA256: testDigest("stall-" + exchange), Nonce: api.ID("stall-" + exchange), Method: exchange, Params: json.RawMessage(`{}`)}
		var result api.Empty
		_, err := channel.exchange(operationCtx, request, &result, nil, false, time.Now().Add(2*time.Second), func() error { return errors.Join(channel.transportAlive(), peer.alive()) })
		waited <- err
		return err
	}
	var besideMu sync.Mutex
	callbacks, concurrent := 0, 0
	beside := func() {
		besideMu.Lock()
		defer besideMu.Unlock()
		callbacks++
		if !manager.helperMu.TryLock() {
			concurrent++
			return
		}
		manager.helperMu.Unlock()
	}
	var loops sync.WaitGroup
	loops.Add(2)
	go func() {
		defer loops.Done()
		for {
			connection, err := ordinary.AcceptUnix()
			if err != nil {
				return
			}
			serveStall(ctx, connection, manager, false, pending, wait, beside)
		}
	}()
	go func() {
		defer loops.Done()
		for {
			connection, err := metadata.AcceptUnix()
			if err != nil {
				return
			}
			loops.Add(1)
			go func() {
				defer loops.Done()
				serveStall(ctx, connection, manager, true, pending, nil, beside)
			}()
		}
	}()
	// The outside broker: its exchange handling calls the component's port.
	brokered := make(chan error, 1)
	go func() {
		data, err := readUnixFrame(server, serverPeer)
		if err != nil {
			brokered <- err
			return
		}
		var request helperRequest
		if err := decodeStrict(data, &request); err != nil {
			brokered <- err
			return
		}
		callErr := callback(ctx)
		response := helperResponse{Protocol: credentialProtocol, Revision: api.ContractRevision, Nonce: request.Nonce, Result: json.RawMessage(`{}`)}
		if callErr != nil {
			response.Result, response.Error = nil, failure(api.CodeUnavailable, "component callback failed")
		}
		brokered <- errors.Join(callErr, writeFrame(server, response))
	}()
	defer func() {
		cancel()
		ordinary.Close()
		metadata.Close()
		loops.Wait()
	}()
	if err := helper.send(ctx, pending); err != nil {
		t.Fatalf("the helper's %s stalled on its own pending credential %s: %v", pending, exchange, err)
	}
	if err := <-waited; err != nil {
		t.Fatalf("the credential %s did not complete inside %s: %v", exchange, pending, err)
	}
	if err := <-brokered; err != nil {
		t.Fatal("the broker's component callback failed:", err)
	}
	besideMu.Lock()
	defer besideMu.Unlock()
	if callbacks != 1 || concurrent != 1 {
		t.Fatalf("the callback was not one metadata read beside the pending %s: callbacks=%d concurrent=%d", pending, callbacks, concurrent)
	}
	if !manager.helperMu.TryLock() {
		t.Fatalf("the completed %s retained helperMu", pending)
	}
	manager.helperMu.Unlock()
	if !manager.operationMu.TryLock() {
		t.Fatalf("the completed %s retained operationMu", pending)
	}
	manager.operationMu.Unlock()
}

// Box 68 and 69: the helper's ordinary prepare waits on the broker's transfer,
// and the transfer calls the private component's runtime port back.
func TestCredentialRuntimeCallback(t *testing.T) {
	helper := newStallHelper(t)
	port := componentRuntimePort(t, helper)
	stallCallback(t, helper, "prepare", "transfer", func(ctx context.Context) error {
		_, err := port(ctx, api.PreparedSpecHandoff{})
		return err
	})
}

// The release refresh: the helper's ordinary release waits on the broker's
// refresh (credlife_linux.go acceptCredentialRefresh), and the broker's
// AcceptCredentialRefresh observes the stopped gate through the private
// component's helper.ObserveGate port (secrets/projection.go:792).
func TestCredentialGateCallback(t *testing.T) {
	helper := newStallHelper(t)
	stallCallback(t, helper, "release", "refresh", componentGatePort(t, helper))
}
