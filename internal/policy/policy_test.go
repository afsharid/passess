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
		"bash": "bash", "bash-5.2": "bash", "node22": "node", "Perl5.30": "perl",
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
}
