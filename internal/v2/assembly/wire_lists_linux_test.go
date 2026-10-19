//go:build linux

package assembly

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/rscan"
)

// A wire type is what one producer hands to admin.EncodeWire (wrapped in
// struct{ Value any } when wrap is set) and what the consumer's strict
// decoder fills (then struct{ Value T }, as credentialComponentSession
// builds it with reflect.StructOf).
type wireType struct {
	label string
	typ   reflect.Type
	wrap  bool
}

func TestWireNilLists(t *testing.T) {
	cases := wireTypes(t)
	seen := map[reflect.Type]bool{}
	for _, c := range cases {
		target := c.typ
		if c.wrap {
			target = reflect.StructOf([]reflect.StructField{{Name: "Value", Type: c.typ}})
		}
		seen[target] = true
		for _, nested := range []bool{false, true} {
			value := wireValue(c.typ, nested, 0)
			if err := wireRoundTrip(value, c.wrap, target); err != nil {
				t.Errorf("%s (%s, nested=%t): %v", c.label, c.typ, nested, err)
			}
		}
	}
	// The two box refusals, each field alone nil inside an otherwise full value.
	authority := fullValue(reflect.TypeFor[api.CredentialProjectionAuthority](), 0)
	authority.FieldByName("Targets").SetZero()
	if err := wireRoundTrip(authority, false, authority.Type()); err != nil {
		t.Errorf("CredentialProjectionAuthority.Targets nil: %v", err)
	}
	metadata := fullValue(reflect.TypeFor[api.ObjectMetadata](), 0)
	metadata.FieldByName("ACL").FieldByName("Participants").SetZero()
	wrapped := reflect.StructOf([]reflect.StructField{{Name: "Value", Type: metadata.Type()}})
	if err := wireRoundTrip(metadata, true, wrapped); err != nil {
		t.Errorf("ObjectACL.Participants nil: %v", err)
	}
	t.Logf("covered %d wire cases, %d distinct decoded types", len(cases), len(seen))
}

// wireRoundTrip uses the real encoder and the real strict decoder.
func wireRoundTrip(value reflect.Value, wrap bool, target reflect.Type) error {
	sent := value.Interface()
	if wrap {
		sent = struct{ Value any }{sent}
	}
	data, err := admin.EncodeWire(sent)
	if err != nil {
		return err
	}
	return api.DecodeObject(data, reflect.New(target).Interface())
}

// wireValue fills every struct, pointer and array; lists stay nil, or with
// nested set hold one element whose own lists are nil.
func wireValue(t reflect.Type, nested bool, depth int) reflect.Value {
	v := reflect.New(t).Elem()
	if depth > 24 {
		return v
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		v.SetBytes([]byte(`{}`))
		return v
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.IsExported() && f.Tag.Get("json") != "-" {
				v.Field(i).Set(wireValue(f.Type, nested, depth+1))
			}
		}
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
		v.Elem().Set(wireValue(t.Elem(), nested, depth+1))
	case reflect.Array:
		for i := 0; i < t.Len(); i++ {
			v.Index(i).Set(wireValue(t.Elem(), nested, depth+1))
		}
	case reflect.Slice:
		if nested && t.Elem().Kind() != reflect.Uint8 {
			v.Set(reflect.Append(v, wireValue(t.Elem(), false, depth+1)))
		}
	case reflect.Map:
		if nested {
			m := reflect.MakeMap(t)
			m.SetMapIndex(reflect.New(t.Key()).Elem(), wireValue(t.Elem(), false, depth+1))
			v.Set(m)
		}
	}
	return v
}

// fullValue gives every list one element, recursively, so a single field set
// back to nil is the only nil list in the value.
func fullValue(t reflect.Type, depth int) reflect.Value {
	v := reflect.New(t).Elem()
	if depth > 24 {
		return v
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		v.SetBytes([]byte(`{}`))
		return v
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if f := t.Field(i); f.IsExported() && f.Tag.Get("json") != "-" {
				v.Field(i).Set(fullValue(f.Type, depth+1))
			}
		}
	case reflect.Pointer:
		v.Set(reflect.New(t.Elem()))
		v.Elem().Set(fullValue(t.Elem(), depth+1))
	case reflect.Array:
		for i := 0; i < t.Len(); i++ {
			v.Index(i).Set(fullValue(t.Elem(), depth+1))
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			v.SetBytes([]byte{1})
		} else {
			v.Set(reflect.Append(v, fullValue(t.Elem(), depth+1)))
		}
	}
	return v
}

// wireTypes enumerates the request and reply types from the method tables
// in the source: the component method map, the component, broker and
// identity session switches, and the helper's credential metadata methods.
func wireTypes(t *testing.T) []wireType {
	var cases []wireType
	known := map[string]reflect.Type{}
	learn := func(roots ...reflect.Type) {
		for _, root := range roots {
			learnTypes(root, known)
		}
	}
	learn(reflect.TypeFor[json.RawMessage](), reflect.TypeFor[api.Empty](), reflect.TypeFor[api.Error](), reflect.TypeFor[credentialArguments](), reflect.TypeFor[credentialStorageInput](),
		reflect.TypeFor[rscan.NativeReleaseScan]())

	// 1. assembly/credowners_linux.go: the methods map. Each argument
	// crosses as struct{ Value In(i) }, the reply as struct{ Value Out(0) }.
	owners := parseGo(t, "credowners_linux.go")
	start := funcDecl(t, owners, "", "startInstalledCredentialOwners")
	params := map[string]int{}
	for _, field := range start.Type.Params.List {
		for _, name := range field.Names {
			params[name.Name] = len(params)
		}
	}
	signature := reflect.TypeOf(startInstalledCredentialOwners)
	table := methodMap(t, start)
	names := sortedKeys(table)
	type entry struct{ ins, outs []reflect.Type }
	entries := map[string]entry{}
	var literals []string
	for _, name := range names {
		switch value := table[name].(type) {
		case *ast.SelectorExpr:
			receiver, ok := value.X.(*ast.Ident)
			index, found := params[receiver.Name]
			if !ok || !found {
				t.Fatalf("method map entry %s has an unknown receiver", name)
			}
			owner := signature.In(index)
			method, ok := owner.MethodByName(value.Sel.Name)
			if !ok {
				t.Fatalf("method map entry %s: %s has no method %s", name, owner, value.Sel.Name)
			}
			fn, skip := method.Type, 1
			if owner.Kind() != reflect.Interface {
				skip = 2
			}
			var e entry
			for i := skip; i < fn.NumIn(); i++ {
				e.ins = append(e.ins, fn.In(i))
			}
			for i := 0; i < fn.NumOut(); i++ {
				e.outs = append(e.outs, fn.Out(i))
			}
			learn(append(e.ins, e.outs...)...)
			entries[name] = e
		case *ast.FuncLit:
			literals = append(literals, name)
		default:
			t.Fatalf("method map entry %s is neither a method value nor a function literal", name)
		}
	}
	for _, name := range literals {
		fn := table[name].(*ast.FuncLit)
		var e entry
		for i, field := range fn.Type.Params.List {
			for range max(1, len(field.Names)) {
				if i > 0 {
					e.ins = append(e.ins, resolveType(t, field.Type, "assembly", known, nil))
				}
			}
		}
		if fn.Type.Results != nil {
			for _, field := range fn.Type.Results.List {
				if types.ExprString(field.Type) == "error" {
					e.outs = append(e.outs, reflect.TypeFor[error]())
				} else {
					e.outs = append(e.outs, resolveType(t, field.Type, "assembly", known, nil))
				}
			}
		}
		entries[name] = e
	}
	errorType := reflect.TypeFor[error]()
	for _, name := range names {
		e := entries[name]
		for i, in := range e.ins {
			cases = append(cases, wireType{"component " + name + " argument " + strconv.Itoa(i), in, true})
		}
		reply := reflect.TypeFor[api.Empty]()
		if len(e.outs) == 2 && e.outs[1] == errorType {
			reply = e.outs[0]
		} else if len(e.outs) != 1 || e.outs[0] != errorType {
			t.Fatalf("method map entry %s returns %v", name, e.outs)
		}
		cases = append(cases, wireType{"component " + name + " reply", reply, true})
	}
	cases = append(cases, wireType{"component arguments", reflect.TypeFor[credentialArguments](), false})

	// 2. assembly/credcomp_linux.go and credbroker_linux.go:
	// each switch's request is the case's `var q T`; replies come from the
	// owning service method, or the literal the case returns.
	identityService, secretsService := reflect.TypeFor[*identity.Service](), reflect.TypeFor[*secrets.Service]()
	out := func(owner reflect.Type, name string) reflect.Type {
		method, ok := owner.MethodByName(name)
		if !ok {
			t.Fatalf("%s has no method %s", owner, name)
		}
		return method.Type.Out(0)
	}
	learn(identityService, secretsService)
	components := parseGo(t, "credcomp_linux.go")
	broker := parseGo(t, "credbroker_linux.go")
	empty, record := reflect.TypeFor[api.Empty](), reflect.TypeFor[api.CredentialProjectionRecord]()
	switches := []struct {
		label   string
		file    *ast.File
		recv    string
		fn      string
		wrap    bool
		replies map[string]reflect.Type
	}{
		{"component", components, "credentialComponentSession", "Call", true, map[string]reflect.Type{
			"identity.authorize": out(identityService, "AuthorizeCredentialProjection")}},
		{"component storage", components, "credentialComponentSession", "storage", true, map[string]reflect.Type{
			"lock": empty, "unlock": empty, "write": empty, "refresh_acquire": empty, "refresh_check": empty, "refresh_close": empty,
			"names": reflect.TypeFor[[]string](), "read": reflect.TypeFor[[]byte](), "refresh_held": reflect.TypeFor[struct{ Held bool }]()}},
		{"identity", components, "credentialIdentitySession", "Call", false, map[string]reflect.Type{
			"authorize": out(identityService, "AuthorizeCredentialProjection"), "check_launch": out(identityService, "CheckLaunchCredentials"),
			"select_worker": out(identityService, "SelectCredentialWorker")}},
		{"broker", broker, "credentialBrokerSession", "Call", false, map[string]reflect.Type{
			"source_versions": reflect.TypeFor[struct{ Sources []api.CredentialSourceVersion }](), "reserve": out(secretsService, "ReserveCredentials"),
			"transfer": out(secretsService, "TransferCredentials"), "acknowledge": out(secretsService, "AcknowledgeCredentials"),
			"begin_withdrawal": out(secretsService, "BeginCredentialWithdrawal"), "finish_withdrawal": out(secretsService, "FinishCredentialWithdrawal"),
			"refresh": out(secretsService, "AcceptCredentialRefresh"), "guard_lock": record, "guard_check": record, "guard_close": empty}},
	}
	for _, s := range switches {
		requests := methodRequests(funcDecl(t, s.file, s.recv, s.fn))
		checkSameMethods(t, s.label, requests, s.replies)
		for _, method := range sortedKeys(requests) {
			if requests[method] == nil {
				t.Fatalf("%s method %s decodes no typed request", s.label, method)
			}
			request := resolveType(t, requests[method], "assembly", known, nil)
			cases = append(cases, wireType{s.label + " " + method + " request", request, false},
				wireType{s.label + " " + method + " reply", s.replies[method], s.wrap})
		}
	}

	// 3. The helper's credential metadata methods (admin/credential_operation.go
	// credentialMetadataMethod), decoded by admin/lease.go's dispatch switch.
	operation := parseGo(t, filepath.Join("..", "admin", "credential_operation.go"))
	lease := parseGo(t, filepath.Join("..", "admin", "lease.go"))
	local := adminTypeSpecs(t)
	metadata := map[string]bool{}
	ast.Inspect(funcDecl(t, operation, "", "credentialMetadataMethod"), func(n ast.Node) bool {
		if literal, ok := n.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			name, _ := strconv.Unquote(literal.Value)
			metadata[name] = true
		}
		return true
	})
	helperReplies := map[string]reflect.Type{
		"credential_peer_verify": empty, "credential_withdrawal_observe": reflect.TypeFor[api.CredentialWithdrawalReceipt](),
		"credential_projection_source": reflect.TypeFor[api.CredentialProjectionAuthority](), "credential_projection_observe": reflect.TypeFor[api.CredentialProjectionReceipt](),
		"credential_projection_observe_id": reflect.TypeFor[api.CredentialProjectionReceipt](), "resolve_runtime": reflect.TypeFor[api.ResolvedRuntime](),
		"credential_gate_observe": reflect.TypeFor[api.ProcessObservation](), "containment_live": resolveType(t, ast.NewIdent("containmentTicket"), "admin", known, local),
	}
	dispatch := methodRequests(funcDecl(t, lease, "leaseManager", "dispatch"))
	requests := map[string]ast.Expr{}
	for name := range metadata {
		expr, ok := dispatch[name]
		if !ok || expr == nil {
			t.Fatalf("helper metadata method %s has no typed case in leaseManager.dispatch", name)
		}
		requests[name] = expr
	}
	checkSameMethods(t, "helper", requests, helperReplies)
	for _, method := range sortedKeys(requests) {
		request := resolveType(t, requests[method], "admin", known, local)
		cases = append(cases, wireType{"helper " + method + " request", request, false},
			wireType{"helper " + method + " reply", helperReplies[method], false})
	}

	// 4. The envelopes themselves (admin/wire.go): the effect lease rides in
	// every helper and credential request.
	for _, name := range []string{"helperRequest", "helperResponse", "credentialResponse"} {
		cases = append(cases, wireType{"envelope " + name, resolveType(t, ast.NewIdent(name), "admin", known, local), false})
	}
	return cases
}

func parseGo(t *testing.T, path string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func funcDecl(t *testing.T, file *ast.File, recv, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		receiver := ""
		if fn.Recv != nil && len(fn.Recv.List) == 1 {
			receiver = strings.TrimPrefix(types.ExprString(fn.Recv.List[0].Type), "*")
		}
		if receiver == recv {
			return fn
		}
	}
	t.Fatalf("function %s.%s not found", recv, name)
	return nil
}

func methodMap(t *testing.T, fn *ast.FuncDecl) map[string]ast.Expr {
	t.Helper()
	table := map[string]ast.Expr{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || types.ExprString(assign.Lhs[0]) != "methods" {
			return true
		}
		literal, ok := assign.Rhs[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("methods is not a map literal")
		}
		for _, element := range literal.Elts {
			pair := element.(*ast.KeyValueExpr)
			name, err := strconv.Unquote(pair.Key.(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			table[name] = pair.Value
		}
		return false
	})
	if len(table) == 0 {
		t.Fatal("methods map not found")
	}
	return table
}

// methodRequests maps each method a function selects (a case label or a
// `method == "x"` test) to the type of the first `var q T` it decodes into;
// a function-wide `var q T` serves methods whose own block declares none.
func methodRequests(fn *ast.FuncDecl) map[string]ast.Expr {
	requests := map[string]ast.Expr{}
	firstVar := func(stmts []ast.Stmt) ast.Expr {
		for _, stmt := range stmts {
			if decl, ok := stmt.(*ast.DeclStmt); ok {
				if gen, ok := decl.Decl.(*ast.GenDecl); ok && gen.Tok == token.VAR {
					if spec := gen.Specs[0].(*ast.ValueSpec); spec.Type != nil {
						return spec.Type
					}
				}
			}
		}
		return nil
	}
	shared := firstVar(fn.Body.List)
	selected := func(name string, block []ast.Stmt) {
		if expr := firstVar(block); expr != nil {
			requests[name] = expr
		} else if _, ok := requests[name]; !ok {
			requests[name] = shared
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CaseClause:
			for _, label := range node.List {
				if literal, ok := label.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					name, _ := strconv.Unquote(literal.Value)
					selected(name, node.Body)
				}
			}
		case *ast.IfStmt:
			if test, ok := node.Cond.(*ast.BinaryExpr); ok && test.Op == token.EQL && types.ExprString(test.X) == "method" {
				if literal, ok := test.Y.(*ast.BasicLit); ok && literal.Kind == token.STRING {
					name, _ := strconv.Unquote(literal.Value)
					selected(name, node.Body.List)
				}
			}
		}
		return true
	})
	return requests
}

func checkSameMethods(t *testing.T, label string, requests map[string]ast.Expr, replies map[string]reflect.Type) {
	t.Helper()
	for name := range requests {
		if _, ok := replies[name]; !ok {
			t.Fatalf("%s method %s is in the source switch but has no reply type here", label, name)
		}
	}
	for name := range replies {
		if _, ok := requests[name]; !ok {
			t.Fatalf("%s method %s has a reply type here but no typed case in the source switch", label, name)
		}
	}
}

// adminTypeSpecs reads admin's own type declarations, for its unexported
// wire types (credentialSourceQuery, helperRequest) no exported API names.
func adminTypeSpecs(t *testing.T) map[string]ast.Expr {
	t.Helper()
	specs := map[string]ast.Expr{}
	for _, name := range []string{"credential_source.go", "credential_verify.go", "containment_types.go", "wire.go"} {
		file := parseGo(t, filepath.Join("..", "admin", name))
		for _, decl := range file.Decls {
			if gen, ok := decl.(*ast.GenDecl); ok && gen.Tok == token.TYPE {
				for _, spec := range gen.Specs {
					spec := spec.(*ast.TypeSpec)
					specs[spec.Name.Name] = spec.Type
				}
			}
		}
	}
	return specs
}

func learnTypes(t reflect.Type, known map[string]reflect.Type) {
	key := strings.ReplaceAll(t.String(), " ", "")
	if _, ok := known[key]; ok {
		return
	}
	known[key] = t
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		learnTypes(t.Elem(), known)
	case reflect.Map:
		learnTypes(t.Key(), known)
		learnTypes(t.Elem(), known)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			learnTypes(t.Field(i).Type, known)
		}
	case reflect.Func:
		for i := 0; i < t.NumIn(); i++ {
			learnTypes(t.In(i), known)
		}
		for i := 0; i < t.NumOut(); i++ {
			learnTypes(t.Out(i), known)
		}
	}
	for i := 0; i < t.NumMethod(); i++ {
		learnTypes(t.Method(i).Type, known)
	}
}

// resolveType turns a source type expression into the reflect type the
// compiled code uses: named types by their reflect name, struct literals and
// local declarations with reflect.StructOf over the same fields and tags.
func resolveType(t *testing.T, expr ast.Expr, pkg string, known map[string]reflect.Type, local map[string]ast.Expr) reflect.Type {
	t.Helper()
	switch e := expr.(type) {
	case *ast.StructType:
		var fields []reflect.StructField
		for _, field := range e.Fields.List {
			var tag reflect.StructTag
			if field.Tag != nil {
				text, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					t.Fatal(err)
				}
				tag = reflect.StructTag(text)
			}
			fieldType := resolveType(t, field.Type, pkg, known, local)
			for _, name := range field.Names {
				fields = append(fields, reflect.StructField{Name: name.Name, Type: fieldType, Tag: tag})
			}
		}
		return reflect.StructOf(fields)
	case *ast.StarExpr:
		return reflect.PointerTo(resolveType(t, e.X, pkg, known, local))
	case *ast.ArrayType:
		if e.Len == nil {
			return reflect.SliceOf(resolveType(t, e.Elt, pkg, known, local))
		}
	case *ast.Ident:
		if types.Universe.Lookup(e.Name) == nil {
			if found, ok := known[pkg+"."+e.Name]; ok {
				return found
			}
			if spec, ok := local[e.Name]; ok {
				return resolveType(t, spec, pkg, known, local)
			}
			t.Fatalf("cannot resolve local type %s.%s", pkg, e.Name)
		}
	}
	key := strings.ReplaceAll(types.ExprString(expr), " ", "")
	found, ok := known[key]
	if !ok {
		t.Fatalf("cannot resolve wire type %s", key)
	}
	return found
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
