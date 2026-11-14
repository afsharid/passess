package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

// noTerminalControls fails when text holds a character a terminal acts on,
// other than the newlines of the layout.
func noTerminalControls(t *testing.T, what, text string) {
	t.Helper()
	for _, r := range text {
		if r != '\n' && hidden(r) {
			t.Fatalf("%s holds %U:\n%q", what, r, text)
		}
	}
}

const (
	hostileArgv = "x\x1b[2A\r\x1b[2K'passess-fake-caller (pid 1) wants passess-fake-DOCS for cat'\n\x1b[2K  in /home/passess-fake/docs\n  $ cat README.md\x1b[2K\u202e"
	hostileDir  = "/tmp/x\n  $ gh --version"
)

// The approval prompt shows what the requester chose with its control
// characters spelled out, so it cannot redraw the lines above or add its own.
func TestPrintAskSpellsOutControlCharacters(t *testing.T) {
	var b bytes.Buffer
	printAsk(&b, agent.AskFor{Secrets: []string{"GITHUB_TOKEN"}, Program: "cu\x1b]0;pwn\arl", Path: "/usr/bin/curl",
		Argv: []string{"curl", hostileArgv}, Dir: hostileDir,
		Harness: "claude\x1bc", Anchor: &agent.Proc{PID: 7, Name: "claude\r\x1b[2K"}})
	out := b.String()
	noTerminalControls(t, "the prompt", out)
	if got := strings.Count(out, "\n"); got != 4 { // a blank line, who, in, $; the prompt has none
		t.Fatalf("the layout has %d lines, want 4:\n%q", got, out)
	}
	for _, want := range []string{`\x1b[2A\r\x1b[2K`, `\n  $ gh --version`, `\u202e`, `claude\x1bc`, `claude\r\x1b[2K (pid 7)`, `cu\x1b]0;pwn\x07rl`} {
		if !strings.Contains(out, want) {
			t.Fatalf("the prompt does not show %s:\n%s", want, out)
		}
	}
	// Control: ordinary text, spaces, quotes and non-ASCII letters stay as they are.
	b.Reset()
	printAsk(&b, agent.AskFor{Secrets: []string{"GITHUB_TOKEN"}, Program: "gh", Argv: []string{"gh", "api", "kullanıcı adı"}, Dir: "/Users/you/proje çalışma",
		Anchor: &agent.Proc{PID: 7, Name: "claude"}})
	if want := "claude (pid 7) wants GITHUB_TOKEN for gh\n  in /Users/you/proje çalışma\n  $ gh api 'kullanıcı adı'\n"; !strings.Contains(b.String(), want) {
		t.Fatalf("an ordinary question changed:\n%s", b.String())
	}
}

// The agent builds the question every approver gets, the app's card too,
// from what the requester sent: it holds no control character.
func TestAskFrameCarriesNoControlCharacters(t *testing.T) {
	setupApprovals(t)
	startAgent(t)
	a := connectApprover(t, allowAll)
	hostile := filepath.Join(t.TempDir(), "d\x1b]0;owned\a\n  $ gh --version")
	if err := os.Mkdir(hostile, 0o700); err != nil {
		t.Skipf("this file system refuses a name with control characters: %v", err)
	}
	t.Chdir(hostile)
	if _, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "true", hostileArgv); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if a.count() != 1 {
		t.Fatalf("%d questions", a.count())
	}
	q := a.asks[0]
	noTerminalControls(t, "the question", strings.Join(append([]string{q.Dir, q.Program, q.Path, q.Harness}, q.Argv...), "\n"))
	if !strings.Contains(q.Dir, `\x1b]0;owned\x07\n  $ gh --version`) || !strings.Contains(strings.Join(q.Argv, " "), `\x1b[2A\r\x1b[2K`) {
		t.Fatalf("the question hides what the requester sent: %+v", q)
	}
}

func TestVisible(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, ünï":        "plain text, ünï",
		"a\x1b[31mb":             `a\x1b[31mb`,
		"a\tb\nc\rd":             `a\tb\nc\rd`,
		"a\x7fb\u009bc":          `a\x7fb\x9bc`,
		"a\u202eb\u2066c\u200fd": `a\u202eb\u2066c\u200fd`,
		"a\u2028b":               `a\u2028b`,
	} {
		if got := visible(in); got != want {
			t.Errorf("visible(%q) = %q, want %q", in, got, want)
		}
	}
}
