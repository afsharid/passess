package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFamily(t *testing.T) {
	for in, want := range map[string]string{
		"python3.14": "python", "python3": "python", "/usr/bin/python": "python",
		"bash": "sh", "bash-5.2": "sh", "dash": "sh", "zsh": "sh", "fish": "sh", "node22": "node",
		"nodejs": "node", "gawk": "awk", "pypy3": "python", "Perl5.30": "perl", "busybox": "busybox",
		"gh": "gh", "base64": "base64", "sha256sum": "sha256sum", "7z": "7z",
	} {
		if got := Family(in); got != want {
			t.Errorf("Family(%q) = %q, want %q", in, got, want)
		}
	}
}

func mustInspect(t *testing.T, argv0 string) Program {
	t.Helper()
	p, err := Inspect(argv0, exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestShellIsRefusedUnlessAllowed(t *testing.T) {
	sh := mustInspect(t, "sh")
	if d := Check("TOKEN", sh, nil); d.Allowed || d.Family != "sh" {
		t.Fatalf("sh without allow list: %+v", d)
	}
	if d := Check("TOKEN", sh, []string{"gh"}); d.Allowed {
		t.Fatalf("sh with allow=[gh]: %+v", d)
	}
	if d := Check("TOKEN", sh, []string{"sh"}); !d.Allowed {
		t.Fatalf("sh with allow=[sh]: %+v", d)
	}

	// Debian's /bin/sh is a symlink to dash; allowing "sh" must cover it.
	for _, other := range []string{"dash", "bash", "zsh"} {
		target, err := exec.LookPath(other)
		if err != nil {
			continue
		}
		link := filepath.Join(t.TempDir(), "sh")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		p := mustInspect(t, link)
		if d := Check("TOKEN", p, []string{"sh"}); !d.Allowed {
			t.Fatalf("sh -> %s with allow=[sh]: %+v (families %v)", other, d, p.Families)
		}
		if d := Check("TOKEN", p, nil); d.Allowed {
			t.Fatalf("sh -> %s without allow: allowed", other)
		}
	}
}

func TestOrdinaryProgram(t *testing.T) {
	ls := mustInspect(t, "ls")
	if d := Check("TOKEN", ls, nil); !d.Allowed {
		t.Fatalf("ls with no allow list: %+v", d)
	}
	if d := Check("TOKEN", ls, []string{"gh"}); d.Allowed {
		t.Fatalf("ls outside allow=[gh]: %+v", d)
	}
	if d := Check("TOKEN", ls, []string{"ls"}); !d.Allowed {
		t.Fatalf("ls with allow=[ls]: %+v", d)
	}
}

func TestDisguisesAreSeenThrough(t *testing.T) {
	dir := t.TempDir()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	shPath, _ = filepath.EvalSymlinks(shPath)
	data, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}

	copied := filepath.Join(dir, "gh")
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "git")
	if err := os.Symlink(shPath, linked); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "deploy")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	envScript := filepath.Join(dir, "tool")
	if err := os.WriteFile(envScript, []byte("#!/usr/bin/env -S python3 -u\nprint(1)\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{copied: "copy of", linked: "", script: "runs under sh", envScript: "runs under python3"}
	for path, why := range cases {
		p := mustInspect(t, path)
		d := Check("TOKEN", p, []string{filepath.Base(path)})
		if d.Allowed {
			t.Fatalf("%s (families %v) was allowed", path, p.Families)
		}
		if why != "" && !strings.Contains(d.Reason, why) {
			t.Fatalf("%s: reason %q does not say %q", path, d.Reason, why)
		}
	}
}

// TestMultiCallBinary builds a busybox-like layout: applets are symlinks to
// one binary, so the applet name decides, and busybox itself stays denied.
func TestMultiCallBinary(t *testing.T) {
	dir := t.TempDir()
	box := filepath.Join(dir, "busybox")
	if err := os.WriteFile(box, []byte("\x7fELF not really busybox"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, applet := range []string{"ls", "sh"} {
		if err := os.Symlink(box, filepath.Join(dir, applet)); err != nil {
			t.Fatal(err)
		}
	}
	look := func(name string) (string, error) {
		if strings.Contains(name, "/") {
			return name, nil
		}
		return exec.LookPath(name)
	}
	check := func(name string) Decision {
		p, err := Inspect(filepath.Join(dir, name), look)
		if err != nil {
			t.Fatal(err)
		}
		return Check("TOKEN", p, nil)
	}
	if d := check("ls"); !d.Allowed {
		t.Fatalf("ls applet refused: %+v", d)
	}
	if d := check("sh"); d.Allowed || d.Family != "sh" {
		t.Fatalf("sh applet allowed: %+v", d)
	}
	if d := check("busybox"); d.Allowed {
		t.Fatalf("busybox itself allowed: %+v", d)
	}
}

// TestSystemMultiCallHardlinks builds the uutils layout of recent Ubuntu: one
// file the system links as base64 and as sleep. The system's sleep runs
// sleep; a copy of that file, or a link to it under another name, does not
// get the same pass.
func TestSystemMultiCallHardlinks(t *testing.T) {
	root := t.TempDir()
	sys := filepath.Join(root, "bin")
	other := filepath.Join(root, "home")
	for _, d := range []string{sys, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	saved := referenceDirs
	referenceDirs = []string{sys}
	t.Cleanup(func() { referenceDirs = saved })

	multi := []byte("\x7fELF not really coreutils")
	if err := os.WriteFile(filepath.Join(sys, "base64"), multi, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{filepath.Join(sys, "sleep"), filepath.Join(other, "mytool")} {
		if err := os.Link(filepath.Join(sys, "base64"), link); err != nil {
			t.Skipf("no hard links here: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(other, "sleep"), multi, 0o755); err != nil {
		t.Fatal(err)
	}
	look := func(name string) (string, error) {
		if strings.Contains(name, "/") {
			return name, nil
		}
		return filepath.Join(sys, name), nil
	}
	check := func(path string) (Decision, Program) {
		p, err := Inspect(path, look)
		if err != nil {
			t.Fatal(err)
		}
		return Check("TOKEN", p, nil), p
	}
	if d, p := check(filepath.Join(sys, "sleep")); !d.Allowed {
		t.Fatalf("the system's sleep refused (families %v): %+v", p.Families, d)
	}
	for _, path := range []string{filepath.Join(sys, "base64"), filepath.Join(other, "mytool"), filepath.Join(other, "sleep")} {
		if d, p := check(path); d.Allowed {
			t.Errorf("%s allowed (families %v)", path, p.Families)
		}
	}
}

func TestEffective(t *testing.T) {
	if got := Effective(nil, nil); got != nil {
		t.Fatalf("no lists: %v", got)
	}
	if got := Effective([]string{"gh", "git"}, nil); len(got) != 2 {
		t.Fatalf("user only: %v", got)
	}
	if got := Effective(nil, []string{"stripe"}); len(got) != 1 || got[0] != "stripe" {
		t.Fatalf("project only: %v", got)
	}
	if got := Effective([]string{"gh", "python3"}, []string{"python", "curl"}); len(got) != 1 || got[0] != "python" {
		t.Fatalf("intersection by family: %v", got)
	}
	if got := Effective([]string{"gh"}, []string{"curl"}); got == nil || len(got) != 0 {
		t.Fatalf("disjoint lists must allow nothing, got %v", got)
	}
	// allow = [] in the user's config locks a secret to no program; a
	// project file must not open it.
	if got := Effective([]string{}, []string{"curl"}); got == nil || len(got) != 0 {
		t.Fatalf("a project widened a secret locked to no program: %v", got)
	}
	if got := Effective([]string{"gh"}, []string{}); got == nil || len(got) != 0 {
		t.Fatalf("a project that allows nothing must narrow to nothing: %v", got)
	}
}

// A caller that restricts PATH to the disguise's own directory must not hide
// the real interpreter from the copy check: the check also looks in fixed
// system directories.
// Every denied family and every alias of one is looked up for renamed
// copies: the list is built from them, so none can drift out of it.
func TestLookupsCoverEveryDeniedName(t *testing.T) {
	for _, set := range []map[string]bool{denied, func() map[string]bool {
		m := map[string]bool{}
		for a := range aliases {
			m[a] = true
		}
		return m
	}()} {
		for name := range set {
			if !slices.Contains(lookups, name) {
				t.Errorf("%s is denied but a renamed copy of it would not be recognized", name)
			}
		}
	}
}

// A renamed copy of an interpreter the old hand-kept list missed (expect,
// tclsh) is seen through like a copy of sh.
func TestRenamedCopiesOfEveryInterpreterAreSeen(t *testing.T) {
	var orig string
	for _, name := range []string{"expect", "tclsh"} {
		if p, err := exec.LookPath(name); err == nil {
			orig, _ = filepath.EvalSymlinks(p)
			break
		}
	}
	if orig == "" {
		t.Skip("neither expect nor tclsh on PATH")
	}
	data, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(t.TempDir(), "buildtool")
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	lookPath := func(name string) (string, error) {
		if name == "buildtool" {
			return copied, nil
		}
		return exec.LookPath(name)
	}
	p, err := Inspect("buildtool", lookPath)
	if err != nil {
		t.Fatal(err)
	}
	if d := Check("TOKEN", p, nil); d.Allowed {
		t.Fatalf("a renamed copy of %s got the secret (families %v)", orig, p.Families)
	}
}

func TestCopyCheckDoesNotDependOnCallerPATH(t *testing.T) {
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	shPath, _ = filepath.EvalSymlinks(shPath)
	data, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	copied := filepath.Join(dir, "gh")
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	onlyDisguise := func(name string) (string, error) {
		if name == "gh" {
			return copied, nil
		}
		return "", exec.ErrNotFound
	}
	p, err := Inspect("gh", onlyDisguise)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range [][]string{nil, {"gh"}} {
		if d := Check("TOKEN", p, allow); d.Allowed {
			t.Fatalf("allow=%v: a renamed copy of sh got the secret (families %v)", allow, p.Families)
		}
	}
}

// A project file only narrows. With no allow list of the user's own, its
// list must not unlock a denied family.
func TestEffectiveProjectCannotUnlockDeniedFamilies(t *testing.T) {
	for _, name := range []string{"sh", "bash", "python3", "node", "env", "base64", "busybox"} {
		got := Effective(nil, []string{name})
		if got == nil || len(got) != 0 {
			t.Errorf("project allow [%s] with no user list gave %v, want an empty list", name, got)
		}
	}
	if got := Effective(nil, []string{"gh", "bash", "git"}); !slices.Equal(got, []string{"gh", "git"}) {
		t.Fatalf("denied names must drop out and the rest stay: %v", got)
	}
	// Control: a list the user wrote keeps the shell the user allowed.
	if got := Effective([]string{"sh"}, []string{"bash"}); !slices.Equal(got, []string{"bash"}) {
		t.Fatalf("a shell the user allowed was narrowed away: %v", got)
	}
	if got := Combine(nil, []string{"sh"}); !slices.Equal(got, []string{"sh"}) {
		t.Fatalf("Combine of two user lists must not filter: %v", got)
	}
}

func TestProjectAllowDoesNotHandShellsTheSecret(t *testing.T) {
	sh := mustInspect(t, "sh")
	for _, project := range [][]string{{"sh"}, {"bash"}, {"sh", "gh"}} {
		if d := Check("TOKEN", sh, Effective(nil, project)); d.Allowed {
			t.Errorf("project %v let a shell receive the secret", project)
		}
	}
	// Control: a project may still name an ordinary program.
	cat := mustInspect(t, "cat")
	if d := Check("TOKEN", cat, Effective(nil, []string{"cat"})); !d.Allowed {
		t.Errorf("project allow [cat] refused cat: %+v", d)
	}
	if d := Check("TOKEN", cat, Effective(nil, []string{"gh"})); d.Allowed {
		t.Errorf("project allow [gh] let cat through")
	}
}

// interpFixture writes a copy and a symlink of the system sh, and returns
// their paths with a directory to put scripts in.
func interpFixture(t *testing.T) (dir, copied, linked string) {
	t.Helper()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH")
	}
	shPath, _ = filepath.EvalSymlinks(shPath)
	data, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}
	dir = t.TempDir()
	copied = filepath.Join(dir, "myint")
	if err := os.WriteFile(copied, data, 0o755); err != nil {
		t.Fatal(err)
	}
	linked = filepath.Join(dir, "myln")
	if err := os.Symlink(shPath, linked); err != nil {
		t.Fatal(err)
	}
	return dir, copied, linked
}

func writeScript(t *testing.T, path, firstLine string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(firstLine+"\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// A script is judged by the file its #! line names, not by that file's name:
// a copy or a link of a shell under another name is still a shell.
func TestShebangInterpreterIsInspected(t *testing.T) {
	dir, copied, linked := interpFixture(t)
	viaCopy := filepath.Join(dir, "t1")
	writeScript(t, viaCopy, "#!"+copied)
	viaLink := filepath.Join(dir, "t2")
	writeScript(t, viaLink, "#!"+linked)
	chained := filepath.Join(dir, "t3")
	writeScript(t, chained, "#!"+viaCopy)
	viaEnv := filepath.Join(dir, "t4")
	writeScript(t, viaEnv, "#!/usr/bin/env myint")
	viaEnvS := filepath.Join(dir, "t5")
	writeScript(t, viaEnvS, "#!/usr/bin/env -S myln -e")
	lookPath := func(name string) (string, error) {
		switch name {
		case "myint":
			return copied, nil
		case "myln":
			return linked, nil
		}
		return exec.LookPath(name)
	}
	for _, path := range []string{viaCopy, viaLink, chained, viaEnv, viaEnvS} {
		p, err := Inspect(path, lookPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, allow := range [][]string{nil, {filepath.Base(path)}} {
			if d := Check("TOKEN", p, allow); d.Allowed {
				t.Errorf("%s with allow=%v reached a shell (families %v)", filepath.Base(path), allow, p.Families)
			}
		}
	}
}

func TestShebangControlsStayAllowed(t *testing.T) {
	dir := t.TempDir()
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("no cat on PATH")
	}
	plain := filepath.Join(dir, "plain")
	writeScript(t, plain, "#!"+cat)
	missing := filepath.Join(dir, "nothing")
	writeScript(t, missing, "#!"+filepath.Join(dir, "missing-interpreter"))
	loop := filepath.Join(dir, "loop")
	writeScript(t, loop, "#!"+loop)
	for _, path := range []string{plain, missing, loop} {
		p, err := Inspect(path, exec.LookPath)
		if err != nil {
			t.Fatal(err)
		}
		if d := Check("TOKEN", p, nil); !d.Allowed {
			t.Errorf("%s was refused (families %v): %+v", filepath.Base(path), p.Families, d)
		}
	}
}

// A script's interpreter swapped after the check must be caught too.
func TestUnchangedCatchesInterpreterSwap(t *testing.T) {
	dir := t.TempDir()
	cat, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("no cat on PATH")
	}
	cat, _ = filepath.EvalSymlinks(cat)
	data, err := os.ReadFile(cat)
	if err != nil {
		t.Fatal(err)
	}
	interp := filepath.Join(dir, "myint")
	if err := os.WriteFile(interp, data, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "t")
	writeScript(t, script, "#!"+interp)
	p, err := Inspect(script, exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Unchanged(); err != nil {
		t.Fatalf("untouched: %v", err)
	}
	shPath, _ := exec.LookPath("sh")
	shPath, _ = filepath.EvalSymlinks(shPath)
	sh, err := os.ReadFile(shPath)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, sh, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, interp); err != nil {
		t.Fatal(err)
	}
	if err := p.Unchanged(); err == nil {
		t.Fatal("a swapped interpreter went unnoticed")
	}
}
