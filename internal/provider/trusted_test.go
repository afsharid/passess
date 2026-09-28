package provider

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A directory the caller puts first on PATH must never supply a backend CLI:
// that program would be handed the vault's credential.
func TestBackendCLIIsNotTakenFromPATH(t *testing.T) {
	dir := t.TempDir()
	name := "passess-fake-backend-cli"
	marker := filepath.Join(dir, "ran")
	script := "#!/bin/sh\n: > " + marker + "\necho forged\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if p, err := LookTrusted(name); err == nil {
		t.Fatalf("LookTrusted found %s on the caller's PATH", p)
	}
	if _, err := (ExecRunner{}).Run(context.Background(), Cmd{Name: name}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Run = %v, want ErrUnavailable", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program on the caller's PATH ran")
	}
	if strings.Contains(TrustedPath(), dir) {
		t.Fatal("TrustedPath includes the caller's PATH")
	}

	// A real system tool is still found.
	if _, err := LookTrusted("sh"); err != nil {
		t.Fatalf("LookTrusted(sh): %v", err)
	}
	if _, err := LookTrusted("../sh"); err == nil {
		t.Fatal("LookTrusted accepted a path")
	}
}

// The CLI's own PATH and HOME are not the caller's either: PATH decides what
// it starts in turn, HOME where it reads its config (a server URL among it).
func TestBaseEnvIgnoresCallerPATHAndHOME(t *testing.T) {
	evil := t.TempDir()
	env := BaseEnv(func(k string) string {
		switch k {
		case "PATH", "HOME", "XDG_CONFIG_HOME":
			return evil
		}
		return ""
	})
	for _, kv := range env {
		if strings.Contains(kv, evil) {
			t.Fatalf("BaseEnv passed the caller's value: %s", kv)
		}
	}
	if !strings.HasPrefix(env[0], "PATH=") {
		t.Fatalf("BaseEnv has no PATH: %v", env)
	}
}
