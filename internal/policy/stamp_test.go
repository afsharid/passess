package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A program replaced or rewritten after it was judged must be caught before
// it runs, even a same-size rewrite with its mtime set back.
func TestUnchangedCatchesASwap(t *testing.T) {
	dir := t.TempDir()
	prog := filepath.Join(dir, "tool")
	if err := os.WriteFile(prog, []byte("#!/bin/cat\nSAFE\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := Inspect(prog, exec.LookPath)
	if err != nil {
		t.Fatal(err)
	}
	if !Check("TOKEN", p, nil).Allowed {
		t.Fatalf("the harmless program was refused: %v", p.Families)
	}
	if err := p.Unchanged(); err != nil {
		t.Fatalf("untouched program reported changed: %v", err)
	}
	fi, err := os.Stat(prog)
	if err != nil {
		t.Fatal(err)
	}
	// Same size, a shell as interpreter, mtime restored.
	if err := os.WriteFile(prog, []byte("#!/bin/sh\necho x\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(prog, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := p.Unchanged(); !errors.Is(err, ErrChanged) {
		t.Fatalf("rewritten program: %v, want ErrChanged", err)
	}

	// Replaced by a rename over it.
	if p, err = Inspect(prog, exec.LookPath); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\necho y\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(other, prog); err != nil {
		t.Fatal(err)
	}
	if err := p.Unchanged(); !errors.Is(err, ErrChanged) {
		t.Fatalf("replaced program: %v, want ErrChanged", err)
	}
}
