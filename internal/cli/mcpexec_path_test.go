package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A configured server's command given by bare name is not looked up on the
// caller's PATH: a program of that name placed first on it must not run and
// receive the server's secrets. An absolute path in the config is used as
// written, and the server's own PATH is not the caller's either.
func TestMCPExecDoesNotTakeTheCommandFromCallerPATH(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "ran")
	planted := filepath.Join(bin, "passess-fake-mcp-server")
	if err := os.WriteFile(planted, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	pathOut := filepath.Join(t.TempDir(), "path")
	setupMCP(t, `
[mcp.bare]
command = ["passess-fake-mcp-server"]
env     = { TOKEN_VAR = "X" }

[mcp.absolute]
command = ["/bin/sh", "-c", 'printf %s "$PATH" > `+pathOut+`']
env     = { TOKEN_VAR = "X" }
`)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, errOut, code := run(t, "mcp-exec", "bare"); code == 0 || !strings.Contains(errOut, "standard install location") {
		t.Fatalf("bare name on the caller's PATH: exit %d, %q", code, errOut)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the program on the caller's PATH ran")
	}

	if _, errOut, code := run(t, "mcp-exec", "absolute"); code != 0 {
		t.Fatalf("absolute command: exit %d, %q", code, errOut)
	}
	got, err := os.ReadFile(pathOut)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), bin) {
		t.Fatalf("the server's PATH includes the caller's: %s", got)
	}
}
