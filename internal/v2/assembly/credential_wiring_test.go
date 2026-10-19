package assembly

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// The runtime graph regression executes the same source adapter with real
// store/broker/planner components. This companion checks the installed factory
// connects that adapter to the real native client before publishing runtime.
func TestInstalledCredentialSource(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "assembly.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	factories := map[string]string{}
	var storedSource string
	var nativeBound, workersBound, published token.Pos
	ast.Inspect(f, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) == 0 || len(assignment.Rhs) != 1 {
			return true
		}
		name, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		call, ok := assignment.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok || selector.Sel.Name != "New" {
			return true
		}
		factories[name.Name] = owner.Name
		if owner.Name == "store" && len(call.Args) == 1 {
			dependencies, ok := call.Args[0].(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, element := range dependencies.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := field.Key.(*ast.Ident)
				if !ok || key.Name != "CredentialProjection" {
					continue
				}
				if value, ok := field.Value.(*ast.Ident); ok {
					storedSource = value.Name
				}
			}
		}
		return true
	})
	if factories[storedSource] != "credn" {
		t.Fatal("installed store omitted the real credential native source")
	}
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		if selector.Sel.Name == "bindRuntime" {
			published = call.Pos()
		}
		if owner.Name != storedSource || len(call.Args) != 1 {
			return true
		}
		argument, ok := call.Args[0].(*ast.Ident)
		if !ok {
			return true
		}
		if selector.Sel.Name == "BindNative" && factories[argument.Name] == "admin" {
			nativeBound = call.Pos()
		}
		if selector.Sel.Name == "BindWorkers" && factories[argument.Name] == "dataworker" {
			workersBound = call.Pos()
		}
		return true
	})
	if nativeBound == 0 || workersBound == 0 || published == 0 || nativeBound >= published || workersBound >= published {
		t.Fatal("installed credential source was not bound to actual native and worker owners before runtime publication")
	}
}

func TestInstalledCredentialValidators(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "assembly.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"CodexValidator": "codex", "HeadlessValidator": "claudock"}
	seen := map[string]bool{}
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "New" {
			return true
		}
		owner, ok := selector.X.(*ast.Ident)
		if !ok || owner.Name != "secrets" {
			return true
		}
		deps, ok := call.Args[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range deps.Elts {
			field, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			name, ok := field.Key.(*ast.Ident)
			if !ok || want[name.Name] == "" {
				continue
			}
			value, ok := field.Value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			kind, ok := value.Type.(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "CredentialValidator" {
				continue
			}
			pkg, ok := kind.X.(*ast.Ident)
			if ok && pkg.Name == want[name.Name] {
				seen[name.Name] = true
			}
		}
		return true
	})
	for field := range want {
		if !seen[field] {
			t.Fatalf("installed credentials omitted the runner-owned %s", field)
		}
	}
}
