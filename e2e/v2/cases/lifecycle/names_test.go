package lifecyclecase

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This is a source-level namespace unit check, not a black-box lifecycle test.
// The fixed dispatch entry points predate this lane. They must keep their names
// because dispatch.go is integration-owned. New types and private helpers have
// a lane prefix; exported interface receiver methods retain their Go names.
func TestCLILaneNames(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..", "internal", "v2", "cli")
	set := token.NewFileSet()
	dispatch, err := parser.ParseFile(set, filepath.Join(root, "dispatch.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fixed := map[string]bool{}
	ast.Inspect(dispatch, func(node ast.Node) bool {
		row, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, keyOK := row.Key.(*ast.BasicLit)
		value, valueOK := row.Value.(*ast.CompositeLit)
		if !keyOK || key.Kind != token.STRING || !valueOK || len(value.Elts) != 2 {
			return true
		}
		name, nameErr := strconv.Unquote(key.Value)
		method, methodOK := value.Elts[0].(*ast.BasicLit)
		handler, handlerOK := value.Elts[1].(*ast.Ident)
		if nameErr != nil || !methodOK || method.Kind != token.STRING || !handlerOK {
			return true
		}
		methodName, methodErr := strconv.Unquote(method.Value)
		if methodErr == nil && (api.Methods[api.Method(methodName)].Owner == "lb-v2-lifecycle" ||
			name == "internal supervisor") {
			fixed[handler.Name] = true
		}
		return true
	})
	if len(fixed) != 17 {
		t.Fatal("frozen lifecycle dispatch entries changed; review namespace exceptions")
	}
	seen := map[string]bool{}
	check := func(name string, bound bool) {
		t.Helper()
		if bound && fixed[name] {
			seen[name] = true
			return
		}
		if !strings.HasPrefix(name, "lbV2Lifecycle") {
			t.Fatalf("shared CLI declaration lacks lane prefix: %s", name)
		}
	}
	for _, filename := range []string{"commands_lifecycle.go", "internal_lifecycle.go"} {
		file, err := parser.ParseFile(set, filepath.Join(root, filename), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				// Exported receiver methods implement external interfaces such
				// as io.Writer.Write. Their receiver type is still lane-prefixed;
				// every private method and every package declaration is checked.
				if declaration.Recv != nil && ast.IsExported(declaration.Name.Name) {
					continue
				}
				check(declaration.Name.Name, declaration.Recv == nil)
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						check(spec.Name.Name, false)
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							check(name.Name, false)
						}
					}
				}
			}
		}
	}
	if len(seen) != len(fixed) {
		t.Fatal("a frozen lifecycle dispatch handler disappeared")
	}
}
