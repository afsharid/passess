package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// At a terminal with no agent detected, passess run still redacts, unless
// the profile opts in with tty = true: neither signal proves a person is
// there, since an agent can open a pseudo-terminal and clear its markers.
func TestRunRedactsAtATerminalUnlessTheProfileOptsIn(t *testing.T) {
	scriptPath, err := exec.LookPath("script")
	if err != nil {
		t.Skip("no script(1) to give passess a terminal")
	}
	noHarness(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	body := `version = 1
[secrets.X]
ref = "env://PASSESS_TEST_TTY_X"
[profiles.plain]
secrets = ["X"]
allow   = ["sh"]
[profiles.tui]
secrets = ["X"]
allow   = ["sh"]
tty     = true
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	atTerminal := func(profile string) string {
		t.Helper()
		argv := []string{binary, "run", profile, "--", "sh", "-c", `echo "<$X>"`}
		var cmd *exec.Cmd
		if runtime.GOOS == "darwin" {
			cmd = exec.Command(scriptPath, append([]string{"-q", "/dev/null"}, argv...)...)
		} else {
			cmd = exec.Command(scriptPath, "-qec", strings.Join(quoteAll(argv), " "), "/dev/null")
		}
		cmd.Env = append(os.Environ(), "PASSESS_CONFIG="+cfg, "PASSESS_TEST_TTY_X="+execValue, "PASSESS_AGENT_SOCK="+filepath.Join(dir, "none.sock"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", profile, err, out)
		}
		return string(out)
	}

	if out := atTerminal("plain"); strings.Contains(out, execValue) || !strings.Contains(out, "<[REDACTED:X]>") {
		t.Fatalf("a profile without tty = true gave the terminal its value:\n%s", out)
	}
	if out := atTerminal("tui"); !strings.Contains(out, "<"+execValue+">") {
		t.Fatalf("tty = true did not give the program the terminal:\n%s", out)
	}
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return out
}
