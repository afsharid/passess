package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/provider"
)

// underChain makes this process look as if chain were its ancestry, for the
// rest of the test.
func underChain(t *testing.T, chain ...agent.Proc) {
	t.Helper()
	saved := selfChain
	t.Cleanup(func() { selfChain = saved })
	selfChain = func() []agent.Proc { return chain }
}

func TestCallerAgentsFromAncestry(t *testing.T) {
	none := func(string) string { return "" }
	chain := []agent.Proc{{Name: "passess"}, {Name: "zsh"}, {Name: "kiro-cli-chat"}, {Name: "login"}}
	if got := callerAgents(none, chain); !slices.Equal(got, []string{"kiro"}) {
		t.Fatalf("kiro has no marker; its process names it: %v", got)
	}
	marker := func(k string) string {
		if k == "CODEX_THREAD_ID" {
			return "t"
		}
		return ""
	}
	if got := callerAgents(marker, chain); !slices.Equal(got, []string{"codex", "kiro"}) {
		t.Fatalf("a marker and an ancestor both count: %v", got)
	}
	if got := callerAgents(none, []agent.Proc{{Name: "passess"}, {Name: "zsh"}, {Name: "Terminal"}}); len(got) != 0 {
		t.Fatalf("a terminal is no agent: %v", got)
	}
}

// The commands that decide who may use a secret see an agent the way the
// commands that hand secrets out do: Kiro sets no marker, and a command
// cleared of markers still has its ancestors.
func TestPolicyCommandsRefuseAnAgentAmongAncestors(t *testing.T) {
	noHarness(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := writeConfig(t, "version = 1\n[secrets.X]\nref = \"env://PASSESS_TEST_X_TOKEN\"\nclients = [\"codex\"]\n")
	before, _ := os.ReadFile(filepath.Join(dir, "config.toml"))
	underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "zsh"}, agent.Proc{Name: "kiro-cli-chat"})
	for _, args := range [][]string{
		{"set", "X", "--clients", "all"},
		{"remove", "X"},
		{"add", "Y", "--ref", "env://PASSESS_TEST_Y_TOKEN", "--clients", "kiro"},
		{"discover"},
	} {
		if _, errOut, code := run(t, args...); code != ExitNoPerm || !strings.Contains(errOut, "not from Kiro") {
			t.Fatalf("%q from Kiro: exit %d, %q", args, code, errOut)
		}
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "config.toml")); string(after) != string(before) {
		t.Fatalf("Kiro changed the config:\n%s", after)
	}
}

// Two changes at once both land: the second waits for the first instead of
// writing over it.
func TestConcurrentChangesAllLand(t *testing.T) {
	noHarness(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var body strings.Builder
	body.WriteString("version = 1\n")
	const n = 8
	for i := range n {
		fmt.Fprintf(&body, "[secrets.S%d]\nref = \"env://PASSESS_TEST_S%d\"\n", i, i)
	}
	dir := writeConfig(t, body.String())
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, errOut, code := run(t, "set", fmt.Sprintf("S%d", i), "--note", fmt.Sprintf("note %d", i)); code != 0 {
				t.Errorf("set S%d: exit %d, %q", i, code, errOut)
			}
		}()
	}
	wg.Wait()
	u, err := config.LoadUser(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if got := u.Secrets[fmt.Sprintf("S%d", i)].Note; got != fmt.Sprintf("note %d", i) {
			t.Errorf("S%d lost its change: note %q", i, got)
		}
	}
}

// inheritedAgents are the coding agents among this test's own ancestors. Run
// from inside one, a command an agent runs for the test is that agent's
// call (the agent reads the real chain), so a clients list has to name it.
func inheritedAgents() []string {
	chain, _ := agent.Ancestry(os.Getpid())
	return callerAgents(func(string) string { return "" }, chain)
}

// strangerAgent is a coding agent the test does not run under, and the
// environment marker that fakes a call from it.
func strangerAgent(t *testing.T) (label, marker string) {
	t.Helper()
	for _, c := range []struct{ id, marker string }{{"codex", "CODEX_THREAD_ID"}, {"cursor", "CURSOR_AGENT"}, {"opencode", "OPENCODE"}} {
		if !slices.Contains(inheritedAgents(), c.id) {
			return detect.Label(c.id), c.marker
		}
	}
	t.Skip("the test runs under every agent it could fake")
	return "", ""
}

func tomlList(ids []string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = tomlString(id)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// setupClients is setup with X connected to the agents the test runs under
// and nothing else; Y is connected to every agent.
func setupClients(t *testing.T) {
	t.Helper()
	noHarness(t)
	dir := setupDir(t)
	body := `version = 1
[secrets.X]
ref     = "env://PASSESS_TEST_X_TOKEN"
allow   = ["sh"]
clients = ` + tomlList(inheritedAgents()) + `
hosts   = ["api.example.com"]
[secrets.Y]
ref   = "env://PASSESS_TEST_Y_TOKEN"
allow = ["sh"]
[profiles.app]
secrets = ["X"]
allow   = ["sh"]
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestClientsGateExec(t *testing.T) {
	bothWays(t, setupClients, testClientsGateExec)
}

func testClientsGateExec(t *testing.T, _ int) {
	if out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran"); code != 0 || out != "ran\n" {
		t.Fatalf("a connected agent: exit %d, %q %q", code, out, errOut)
	}
	label, marker := strangerAgent(t)
	t.Setenv(marker, "1")
	out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "echo ran")
	if code != ExitNoPerm || out != "" || !strings.Contains(errOut, "X is not connected to "+label) || !strings.Contains(errOut, "Passess.app") {
		t.Fatalf("an agent X is not connected to: exit %d, %q %q", code, out, errOut)
	}
	// No clients list: every agent, as before.
	if out, errOut, code := run(t, "exec", "-s", "Y", "--", "sh", "-c", "echo ran"); code != 0 || out != "ran\n" {
		t.Fatalf("Y: exit %d, %q %q", code, out, errOut)
	}
}

// run, http and the other in-process paths ask the same question.
func TestClientsGateInProcessPaths(t *testing.T) {
	setupClients(t)
	if _, errOut, code := run(t, "run", "app", "--", "sh", "-c", "true"); code != 0 {
		t.Fatalf("run, connected: exit %d, %q", code, errOut)
	}
	label, marker := strangerAgent(t)
	t.Setenv(marker, "1")
	for _, args := range [][]string{
		{"run", "app", "--", "sh", "-c", "true"},
		{"http", "-s", "X", "-H", "Authorization: Bearer {{X}}", "https://api.example.com/"},
	} {
		if _, errOut, code := run(t, args...); code != ExitNoPerm || !strings.Contains(errOut, "X is not connected to "+label) {
			t.Fatalf("%s: exit %d, %q", args[0], code, errOut)
		}
	}
}

// add, set and remove change the config the way the menu bar app asks, and
// only for a person: under an agent they refuse and leave the file alone.
func TestAddSetRemove(t *testing.T) {
	noHarness(t)
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := writeConfig(t, `version = 1
[secrets.X]
ref = "env://PASSESS_TEST_X_TOKEN"

[profiles.app]
secrets = ["X"]
allow   = ["sh"]
`)
	cfg := filepath.Join(dir, "config.toml")
	load := func() *config.User {
		t.Helper()
		u, err := config.LoadUser(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	mustRun := func(args ...string) {
		t.Helper()
		if _, errOut, code := run(t, args...); code != 0 {
			t.Fatalf("%q: exit %d, %q", args, code, errOut)
		}
	}

	mustRun("add", "NEW", "--ref", "env://PASSESS_TEST_NEW", "--clients", "codex,claude-code", "--approve")
	if s := load().Secrets["NEW"]; !s.Approve || strings.Join(s.Clients, ",") != "claude-code,codex" {
		t.Fatalf("after add: %+v", s)
	}
	if _, errOut, code := run(t, "add", "BAD", "--ref", "env://PASSESS_TEST_BAD", "--clients", "notepad"); code != ExitUsage ||
		!strings.Contains(errOut, "not a coding agent") {
		t.Fatalf("unknown agent: exit %d, %q", code, errOut)
	}

	mustRun("set", "NEW", "--clients", "none")
	if s := load().Secrets["NEW"]; s.Clients == nil || len(s.Clients) != 0 {
		t.Fatalf("none: %+v", s)
	}
	mustRun("set", "NEW", "--clients", "all", "--approve", "false", "--note", "from the app")
	if s := load().Secrets["NEW"]; s.Clients != nil || s.Approve || s.Note != "from the app" {
		t.Fatalf("all: %+v", s)
	}
	data, _ := os.ReadFile(cfg)
	if strings.Contains(string(data), "clients") || strings.Contains(string(data), "approve") {
		t.Fatalf("defaults are written by leaving the key out:\n%s", data)
	}

	before, _ := os.ReadFile(cfg)
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"set", "MISSING", "--approve", "true"}, ExitConfig, "MISSING is not defined"},
		{[]string{"set", "NEW"}, ExitUsage, "Usage"},
		{[]string{"set", "NEW", "--approve", "maybe"}, ExitUsage, "true or false"},
		{[]string{"remove", "X"}, ExitConfig, "profile app"},
		{[]string{"remove", "MISSING"}, ExitConfig, "MISSING is not defined"},
	} {
		if _, errOut, code := run(t, c.args...); code != c.code || !strings.Contains(errOut, c.want) {
			t.Fatalf("%q: exit %d, %q", c.args, code, errOut)
		}
	}
	if after, _ := os.ReadFile(cfg); string(after) != string(before) {
		t.Fatalf("a refused change touched the config:\n%s", after)
	}

	t.Setenv("CLAUDECODE", "1")
	for _, args := range [][]string{{"set", "NEW", "--clients", "all"}, {"remove", "NEW"}, {"discover"}} {
		if _, errOut, code := run(t, args...); code != ExitNoPerm || !strings.Contains(errOut, "Passess.app") {
			t.Fatalf("%q under an agent: exit %d, %q", args, code, errOut)
		}
	}
	if after, _ := os.ReadFile(cfg); string(after) != string(before) {
		t.Fatalf("an agent changed the config:\n%s", after)
	}
	t.Setenv("CLAUDECODE", "")

	mustRun("remove", "NEW")
	if _, ok := load().Secrets["NEW"]; ok {
		t.Fatal("NEW is still there")
	}
	// The remove kept the file as it was before it.
	backups, _ := filepath.Glob(filepath.Join(os.Getenv("XDG_STATE_HOME"), "passess", "backups", "*", "*config.toml"))
	kept := false
	for _, b := range backups {
		if data, err := os.ReadFile(b); err == nil && strings.Contains(string(data), "[secrets.NEW]") {
			kept = true
		}
	}
	if !kept {
		t.Fatalf("no backup holds NEW (%d backups)", len(backups))
	}
}

func TestListShowsClients(t *testing.T) {
	noHarness(t)
	writeConfig(t, `version = 1
[secrets.ALL]
ref = "env://A"
[secrets.NONE]
ref     = "env://B"
clients = []
[secrets.SOME]
ref     = "env://C"
clients = ["codex"]
approve = true
[mcp.tool]
command = ["tool"]
env     = { TOKEN = "SOME" }
`)
	out, errOut, code := run(t, "list", "--json")
	if code != 0 {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	var got struct {
		Secrets []struct {
			Name    string    `json:"name"`
			Clients *[]string `json:"clients"`
			Approve bool      `json:"approve"`
			MCP     []string  `json:"mcp"`
			Refs    []string  `json:"refs"`
		} `json:"secrets"`
		Agents []detect.Agent `json:"agents"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Agents) != len(detect.Agents) || got.Agents[0].Label != "Claude Code" {
		t.Fatalf("agents = %+v", got.Agents)
	}
	byName := map[string]int{}
	for i, s := range got.Secrets {
		byName[s.Name] = i
	}
	all, none, some := got.Secrets[byName["ALL"]], got.Secrets[byName["NONE"]], got.Secrets[byName["SOME"]]
	if all.Clients != nil || none.Clients == nil || len(*none.Clients) != 0 || some.Clients == nil || (*some.Clients)[0] != "codex" {
		t.Fatalf("clients: all %v, none %v, some %v", all.Clients, none.Clients, some.Clients)
	}
	if !some.Approve || strings.Join(some.MCP, ",") != "tool" || some.Refs[0] != "env://C" {
		t.Fatalf("SOME = %+v", some)
	}
	text, _, _ := run(t, "list")
	if !strings.Contains(text, "AGENTS") || !strings.Contains(text, "none") || !strings.Contains(text, "codex") {
		t.Fatalf("text list:\n%s", text)
	}
}

const (
	discProject = "0b2f6c1e-1d2e-4a5b-9c8d-7e6f5a4b3c2d"
	discValue   = "passess-fake-discover-value-0123456789"
)

type discoverFake struct{ t *testing.T }

func (f discoverFake) Run(_ context.Context, c provider.Cmd) (provider.Result, error) {
	switch strings.Join(c.Args[:2], " ") {
	case "secret list":
		item := func(id, key, project string) string {
			p := `null`
			if project != "" {
				p = `"` + project + `"`
			}
			created := ""
			if key == "NEW_KEY" {
				created = `,"creationDate":"2026-10-09T08:15:23.123456Z"`
			}
			return `{"id":"` + id + `","key":"` + key + `","value":"` + discValue + `","projectId":` + p + created + `}`
		}
		return provider.Result{Stdout: []byte("[" + strings.Join([]string{
			item("10000000-0000-4000-8000-000000000001", "KNOWN", discProject),
			item("10000000-0000-4000-8000-000000000002", "OTHER", discProject),
			item("10000000-0000-4000-8000-000000000003", "nvidia-nim", discProject),
			item("10000000-0000-4000-8000-000000000004", "NEW_KEY", discProject),
			item("10000000-0000-4000-8000-000000000005", "DUP", discProject),
			item("10000000-0000-4000-8000-000000000006", "DUP", discProject),
			item("10000000-0000-4000-8000-000000000007", "loose", ""),
		}, ",") + "]")}, nil
	case "project list":
		return provider.Result{Stdout: []byte(`[{"id":"` + discProject + `","name":"ai-stack"}]`)}, nil
	}
	f.t.Fatalf("unexpected bws %q", c.Args)
	return provider.Result{}, nil
}

// discover names the vault's secrets passess has no reference to, with the
// command that adds each, and never a value.
func TestDiscover(t *testing.T) {
	noHarness(t)
	writeConfig(t, `version = 1
[secrets.KNOWN]
ref = "bws://ai-stack/KNOWN"
[secrets.OTHER_NAME]
ref = "bws://10000000-0000-4000-8000-000000000002"
[secrets.LOOSE]
ref = "env://PASSESS_TEST_LOOSE"
`)
	saved := discoverRunner
	t.Cleanup(func() { discoverRunner = saved })
	discoverRunner = discoverFake{t}

	out, errOut, code := run(t, "discover", "--json")
	if code != 0 {
		t.Fatalf("no token: exit %d, %q", code, errOut)
	}
	if !strings.Contains(out, `"ok": false`) || !strings.Contains(out, `"state": "not-set-up"`) || !strings.Contains(out, "no bws access token") {
		t.Fatalf("without a token discover says so:\n%s", out)
	}

	t.Setenv("BWS_ACCESS_TOKEN", "passess-fake-bws-machine-token-0123456789")
	out, errOut, code = run(t, "discover", "--json")
	if code != 0 {
		t.Fatalf("exit %d, %q", code, errOut)
	}
	if strings.Contains(out+errOut, discValue) {
		t.Fatal("discover printed a value")
	}
	var got discoverOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	want := []discovered{
		{Key: "loose", Name: "LOOSE", Ref: "bws://10000000-0000-4000-8000-000000000007", NameTaken: true},
		{Key: "DUP", Project: "ai-stack", Name: "DUP", Ref: "bws://10000000-0000-4000-8000-000000000005"},
		{Key: "DUP", Project: "ai-stack", Name: "DUP", Ref: "bws://10000000-0000-4000-8000-000000000006"},
		{Key: "NEW_KEY", Project: "ai-stack", Name: "NEW_KEY", Ref: "bws://" + discProject + "/NEW_KEY", Created: "2026-10-09T08:15:23Z"},
		{Key: "nvidia-nim", Project: "ai-stack", Name: "NVIDIA_NIM", Ref: "bws://10000000-0000-4000-8000-000000000003"},
	}
	if !slices.Equal(got.Secrets, want) || len(got.Backends) != 1 || !got.Backends[0].OK {
		t.Fatalf("got %+v", got)
	}

	text, _, _ := run(t, "discover")
	if !strings.Contains(text, "passess add NEW_KEY --ref bws://"+discProject+"/NEW_KEY") {
		t.Fatalf("text:\n%s", text)
	}
}

// A name from the vault reaches the terminal as text: whoever writes to the
// vault must not move the cursor or redraw discover's table.
func TestVaultNamesArePrintable(t *testing.T) {
	for in, want := range map[string]string{
		"OPENAI_API_KEY":   "OPENAI_API_KEY",
		"x\x1b[2K\x1b[1Ay": "x[2K[1Ay",
		"a\tb":             "a b",
		"p\u009b31mq":      "p31mq",
		"line\nbreak\r":    "linebreak",
		"projeçt":          "projeçt",
	} {
		if got := vaultName(in); got != want {
			t.Errorf("vaultName(%q) = %q, want %q", in, got, want)
		}
	}
}
