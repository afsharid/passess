package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
)

func TestHelper(t *testing.T) {
	dir := setupDir(t)
	body := `version = 1
[secrets.KEY]
ref   = "env://PASSESS_TEST_X_TOKEN"
allow = ["passess-helper"]
[secrets.OTHER]
ref = "env://PASSESS_TEST_X_TOKEN"
[secrets.GATED]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["passess-helper"]
approve = true
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, errOut, code := run(t, "helper", "KEY"); code != 0 || out != execValue+"\n" {
		t.Fatalf("an opted-in secret: exit %d, %q", code, errOut)
	}
	out, errOut, code := run(t, "helper", "OTHER")
	if code != ExitNoPerm || out != "" || !strings.Contains(errOut, `add "passess-helper" to secrets.OTHER.allow`) {
		t.Fatalf("a secret that did not opt in: exit %d, %q, %q", code, out, errOut)
	}
	if _, errOut, code := run(t, "helper", "GATED"); code != ExitNoPerm || !strings.Contains(errOut, "no agent is running") {
		t.Fatalf("a secret that needs approval, no agent: exit %d, %q", code, errOut)
	}
	if _, _, code := run(t, "helper", "NOPE"); code != ExitConfig {
		t.Fatalf("undefined: exit %d", code)
	}
	if _, _, code := run(t, "helper"); code != ExitUsage {
		t.Fatalf("no name: exit %d", code)
	}
}

// A desktop app asks passess helper for the keys the user connected to it by
// name, and only its own process does: not its agent's shell (ADR 11).
func TestHelperForAnApp(t *testing.T) {
	dir := setupDir(t)
	noHarness(t)
	body := `version = 1
[secrets.NAMED]
ref     = "env://PASSESS_TEST_X_TOKEN"
clients = ["codex", "dsh"]
[secrets.EVERY]
ref = "env://PASSESS_TEST_X_TOKEN"
[secrets.ELSEWHERE]
ref     = "env://PASSESS_TEST_X_TOKEN"
clients = ["codex"]
[secrets.OPTED]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["passess-helper"]
clients = ["codex"]
[secrets.NARROW]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["gh"]
clients = ["dsh"]
[secrets.NARROWOPTED]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["gh", "passess-helper"]
clients = ["dsh"]
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	dsh := agent.Proc{Name: "DeepSeek Harness"}
	underChain(t, agent.Proc{Name: "passess"}, dsh)
	if out, errOut, code := run(t, "helper", "NAMED"); code != 0 || out != execValue+"\n" {
		t.Fatalf("connected to the app by name: exit %d, %q", code, errOut)
	}
	for _, name := range []string{"EVERY", "ELSEWHERE"} {
		out, errOut, code := run(t, "helper", name)
		if code != ExitNoPerm || out != "" || !strings.Contains(errOut, "not connected to DeepSeek Harness by name") {
			t.Fatalf("%s: exit %d, %q, %q", name, code, out, errOut)
		}
	}
	if out, errOut, code := run(t, "helper", "OPTED"); code != ExitNoPerm || out != "" || !strings.Contains(errOut, "not connected to DeepSeek Harness") {
		t.Fatalf("opted in but connected elsewhere: exit %d, %q, %q", code, out, errOut)
	}
	// Any program can take the app's name: a secret narrowed to some programs
	// does not reach it unless it opts in to passess helper itself.
	if out, errOut, code := run(t, "helper", "NARROW"); code != ExitNoPerm || out != "" || !strings.Contains(errOut, "process name any program can take") {
		t.Fatalf("narrowed by allow: exit %d, %q, %q", code, out, errOut)
	}
	if out, errOut, code := run(t, "helper", "NARROWOPTED"); code != 0 || out != execValue+"\n" {
		t.Fatalf("narrowed, opted in, connected by name: exit %d, %q", code, errOut)
	}

	underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "bash"}, dsh)
	if out, errOut, code := run(t, "helper", "NAMED"); code != ExitNoPerm || out != "" || !strings.Contains(errOut, "may not go to passess helper") {
		t.Fatalf("the app's agent through a shell: exit %d, %q, %q", code, out, errOut)
	}
	underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "zsh"}, agent.Proc{Name: "Terminal"})
	if out, _, code := run(t, "helper", "NAMED"); code != ExitNoPerm || out != "" {
		t.Fatalf("a terminal: exit %d, %q", code, out)
	}
}
