package accesschange_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/identity/accesschange"
)

const accesschangeImport = "github.com/plexusone/systemforge/identity/accesschange"

var reasonFormat = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// moduleRoot returns the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// declaredReasons returns the Reason constants declared in accesschange.go,
// by constant name.
func declaredReasons(t *testing.T) map[string]string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "accesschange.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			if id, ok := vs.Type.(*ast.Ident); !ok || id.Name != "Reason" {
				continue
			}
			for i, name := range vs.Names {
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok {
					t.Fatalf("reason %s is not a string literal", name.Name)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatal(err)
				}
				out[name.Name] = v
			}
		}
	}
	return out
}

// TestRegistry checks the registry itself: every declared reason is
// registered, each is well-formed, and unknown reasons are rejected.
func TestRegistry(t *testing.T) {
	declared := declaredReasons(t)
	var values []string
	for name, v := range declared {
		values = append(values, v)
		if !accesschange.Reason(v).Valid() {
			t.Errorf("constant %s = %q is declared but not in the registry (accesschange.Reasons)", name, v)
		}
		if !reasonFormat.MatchString(v) || len(v) > 64 {
			t.Errorf("reason %q is not lower snake case of at most 64 characters", v)
		}
	}
	for _, r := range accesschange.Reasons() {
		if !slices.Contains(values, string(r)) {
			t.Errorf("registered reason %q has no constant", r)
		}
	}
	if got := len(accesschange.Reasons()); got != len(slices.Compact(slices.Sorted(slices.Values(values)))) {
		t.Errorf("registry has %d reasons, %d distinct constants are declared", got, len(values))
	}

	err := accesschange.Reason("grant_widened").Validate()
	if err == nil || !strings.Contains(err.Error(), `"grant_widened"`) {
		t.Errorf("Validate(unknown) = %v, want an error naming the reason", err)
	}
	if accesschange.Reason("").Valid() {
		t.Error("the empty reason is valid")
	}
}

// TestReasonsAreDocumented fails when a registered reason has no row in the
// reason table of the authorization architecture page, or the table lists
// a reason that is not registered.
func TestReasonsAreDocumented(t *testing.T) {
	page := filepath.Join(moduleRoot(t), "docs", "design", "architecture", "authorization.md")
	data, err := os.ReadFile(page) //nolint:gosec // a fixed path under the module root
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(data), "\n### Access-change reasons\n")
	if !ok {
		t.Fatal(`authorization.md has no "### Access-change reasons" section`)
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	row := regexp.MustCompile("(?m)^\\| `([^`]+)` \\|")
	documented := map[string]bool{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		documented[m[1]] = true
	}
	for _, r := range accesschange.Reasons() {
		if !documented[string(r)] {
			t.Errorf("reason %q has no row in the reason table of authorization.md", r)
		}
		delete(documented, string(r))
	}
	for r := range documented {
		t.Errorf("authorization.md documents %q, which is not a registered reason", r)
	}
}

// TestCallSitesUseRegisteredReasons parses every Go file of the module and
// fails when an accesschange.Change is built with a reason that is not one
// of the registered constants, or a reason is converted from a string that
// is not registered.
func TestCallSitesUseRegisteredReasons(t *testing.T) {
	root := moduleRoot(t)
	declared := declaredReasons(t)
	fset := token.NewFileSet()
	sites := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || filepath.Dir(path) == filepath.Join(root, "identity", "accesschange") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == accesschangeImport {
				local = "accesschange"
				if imp.Name != nil {
					local = imp.Name.Name
				}
			}
		}
		if local == "" {
			return nil
		}
		isPkgSel := func(e ast.Expr, name string) bool {
			sel, ok := e.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			x, ok := sel.X.(*ast.Ident)
			return ok && x.Name == local && sel.Sel.Name == name
		}
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				if !isPkgSel(n.Type, "Change") {
					return true
				}
				for _, el := range n.Elts {
					kv, ok := el.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Reason" {
						continue
					}
					sites++
					sel, ok := kv.Value.(*ast.SelectorExpr)
					if !ok || !isPkgSel(sel, sel.Sel.Name) {
						t.Errorf("%s: Reason must be a registered accesschange constant", rel)
						continue
					}
					v, ok := declared[sel.Sel.Name]
					if !ok || !accesschange.Reason(v).Valid() {
						t.Errorf("%s: accesschange.%s is not a registered reason", rel, sel.Sel.Name)
					}
				}
			case *ast.CallExpr:
				if len(n.Args) != 1 || !isPkgSel(n.Fun, "Reason") {
					return true
				}
				lit, ok := n.Args[0].(*ast.BasicLit)
				if !ok {
					return true
				}
				if v, err := strconv.Unquote(lit.Value); err != nil || !accesschange.Reason(v).Valid() {
					t.Errorf("%s: accesschange.Reason(%s) is not a registered reason", rel, lit.Value)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if sites == 0 {
		t.Fatal("found no accesschange.Change call sites; the scan is broken")
	}
}
