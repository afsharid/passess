package policy

import (
	"os"
	"os/exec"
	"path/filepath"
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
