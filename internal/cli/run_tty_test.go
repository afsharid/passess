package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// At a terminal with no agent seen, passess run still redacts, unless the
// profile opts in with tty = true: neither signal proves a person is there,
// since an agent can open a pseudo-terminal, clear its markers and detach.
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
	atTerminal := func(passess, profile string) string {
		t.Helper()
		argv := []string{passess, "run", profile, "--", "sh", "-c", `echo "<$X>"`}
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

	redacted := func(out string) bool {
		return !strings.Contains(out, execValue) && strings.Contains(out, "<[REDACTED:X]>")
	}

	if out := atTerminal(binary, "plain"); !redacted(out) {
		t.Fatalf("a profile without tty = true gave the terminal its value:\n%s", out)
	}
	// Run from inside a coding agent, passess sees it among its ancestors and
	// keeps redacting.
	if agents := inheritedAgents(); len(agents) > 0 {
		if out := atTerminal(binary, "tui"); !redacted(out) {
			t.Fatalf("tty = true gave the terminal its value under %v:\n%s", agents, out)
		}
	} else if out := atTerminal(binary, "tui"); !strings.Contains(out, "<"+execValue+">") {
		t.Fatalf("tty = true did not give the program the terminal:\n%s", out)
	}

	// Kiro sets no marker; passess knows it by its process name, which the
	// kernel takes from the executable's file name. A copy of passess named
	// kiro-cli-chat is such a process.
	exe, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	kiro := filepath.Join(dir, "kiro-cli-chat")
	if err := os.WriteFile(kiro, exe, 0o755); err != nil {
		t.Fatal(err)
	}
	if out := atTerminal(kiro, "tui"); !redacted(out) {
		t.Fatalf("tty = true gave Kiro the terminal:\n%s", out)
	}
}

func quoteAll(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return out
}
