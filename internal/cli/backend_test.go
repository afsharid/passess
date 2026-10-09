package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/provider"
)

const backendToken = "0.fake-machine-token-for-tests"

// keychainFake is a keychain that holds what it was given.
type keychainFake struct {
	t      *testing.T
	stored *string
}

func (f keychainFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	switch {
	case len(c.Args) == 1 && c.Args[0] == "-i": // security -i: the add command on stdin, never in argv
		line := string(c.Stdin)
		if !strings.Contains(line, `-s "passess" -a "bws"`) {
			f.t.Errorf("stored under the wrong item: %q", line)
		}
		*f.stored = backendToken
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "find-generic-password":
		return provider.Result{Stdout: []byte(*f.stored + "\n")}, nil
	case len(c.Args) > 0 && c.Args[0] == "store": // secret-tool
		*f.stored = string(c.Stdin)
		return provider.Result{}, nil
	case len(c.Args) > 0 && c.Args[0] == "lookup":
		return provider.Result{Stdout: []byte(*f.stored)}, nil
	}
	f.t.Fatalf("unexpected command %v", c.Args)
	return provider.Result{}, nil
}

func TestBackendBWS(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("keychain:// is macOS and Linux")
	}
	noHarness(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "passess", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	var stored string
	saved := backendRunner
	t.Cleanup(func() { backendRunner = saved })
	backendRunner = keychainFake{t, &stored}

	run := func(stdin string, args ...string) (string, string, int) {
		t.Helper()
		var out, errb strings.Builder
		code := Main(args, strings.NewReader(stdin), &out, &errb)
		return out.String(), errb.String(), code
	}
	if _, errOut, code := run("\n", "backend", "bws"); code != ExitUsage || !strings.Contains(errOut, "one line") {
		t.Fatalf("an empty token: exit %d, %q", code, errOut)
	}
	out, errOut, code := run(backendToken+"\n", "backend", "bws")
	if code != 0 || stored != backendToken || strings.Contains(out+errOut, backendToken) {
		t.Fatalf("store: exit %d, %q %q", code, out, errOut)
	}
	if data, err := os.ReadFile(cfg); err != nil || string(data) != "version = 1\n" {
		t.Fatalf("a missing config is started: %q, %v", data, err)
	}

	// A config that reads the token from elsewhere is not quietly ignored.
	if err := os.WriteFile(cfg, []byte("version = 1\n[backends.bws]\naccess_token = \"keychain://other/bws\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(backendToken, "backend", "bws"); code != ExitConfig || !strings.Contains(errOut, "keychain://other/bws") {
		t.Fatalf("a token kept elsewhere: exit %d, %q", code, errOut)
	}

	// Under a coding agent it is refused: the token opens the vault.
	t.Setenv("CLAUDECODE", "1")
	if _, _, code := run(backendToken, "backend", "bws"); code != ExitNoPerm {
		t.Fatalf("under an agent: exit %d", code)
	}
}
