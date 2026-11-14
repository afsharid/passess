package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/agent"
	"github.com/afsharid/passess/internal/detect"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", cfg)
	t.Chdir(dir)
	return dir
}

func TestListAndProjectNeeds(t *testing.T) {
	dir := writeConfig(t, `version = 1
[secrets.GITHUB_TOKEN]
ref   = "keychain://passess/github"
allow = ["gh", "git"]
note  = "repo:read"
[secrets.DB_URL]
ref = ["env://DATABASE_URL", "keychain://passess/db"]
[secrets.LOCKED]
ref   = "keychain://passess/locked"
allow = []
`)
	if err := os.WriteFile(filepath.Join(dir, "passess.toml"), []byte("version = 1\n[needs.DB_URL]\n[needs.STRIPE_KEY]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, "list", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var got listOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Secrets) != 3 || got.Secrets[0].Name != "DB_URL" || !got.Secrets[0].Project || got.Secrets[1].Project {
		t.Fatalf("secrets = %+v", got.Secrets)
	}
	if strings.Join(got.Secrets[0].Backends, ",") != "env,keychain" || strings.Join(got.Secrets[1].Allow, ",") != "gh,git" {
		t.Fatalf("details = %+v", got.Secrets)
	}
	// allow = [] is no program; without allow_none it would read as any.
	if l := got.Secrets[2]; l.Name != "LOCKED" || !l.AllowNone || len(l.Allow) != 0 || got.Secrets[0].AllowNone || got.Secrets[1].AllowNone {
		t.Fatalf("allow_none = %+v", got.Secrets)
	}
	if !strings.Contains(out, `"allow_none": true`) && !strings.Contains(out, `"allow_none":true`) {
		t.Fatalf("list --json lacks allow_none:\n%s", out)
	}
	if len(got.Missing) != 1 || got.Missing[0] != "STRIPE_KEY" {
		t.Fatalf("missing = %v", got.Missing)
	}
	human, _, _ := run(t, "list")
	for _, want := range []string{"DB_URL *", "repo:read", "missing: the project needs STRIPE_KEY"} {
		if !strings.Contains(human, want) {
			t.Fatalf("list output lacks %q:\n%s", want, human)
		}
	}
}

func TestCheckReportsStatesWithoutValues(t *testing.T) {
	writeConfig(t, `version = 1
[secrets.PRESENT]
ref = ["env://PASSESS_TEST_ABSENT", "env://PASSESS_TEST_PRESENT_TOKEN"]
[secrets.ABSENT]
ref = "env://PASSESS_TEST_ABSENT"
[secrets.LATER]
ref = "vault://secret/app#token"
`)
	t.Setenv("PASSESS_TEST_PRESENT_TOKEN", execValue)
	t.Setenv("VAULT_ADDR", "") // no vault configured: unavailable, deterministically
	t.Setenv("BAO_ADDR", "")
	out, _, code := run(t, "check", "--json", "PRESENT", "ABSENT", "LATER", "UNDEFINED")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if strings.Contains(out, execValue) {
		t.Fatal("check printed a value")
	}
	var got checkOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"PRESENT": stateOK, "ABSENT": stateMissing, "LATER": stateUnavailable, "UNDEFINED": stateUndefined}
	for _, c := range got.Secrets {
		if c.State != want[c.Name] {
			t.Errorf("%s: state %s, want %s (%s)", c.Name, c.State, want[c.Name], c.Detail)
		}
	}
	if got.Secrets[0].From != "env://PASSESS_TEST_PRESENT_TOKEN" {
		t.Fatalf("from = %q", got.Secrets[0].From)
	}
	if _, _, code := run(t, "check", "PRESENT"); code != 0 {
		t.Fatalf("all ok: exit %d", code)
	}
}

func TestAddCreatesAndAppends(t *testing.T) {
	noHarness(t) // add refuses under an agent; see TestAddUnderAHarness
	dir := t.TempDir()
	cfg := filepath.Join(dir, "sub", "config.toml")
	t.Setenv("PASSESS_CONFIG", cfg)
	t.Chdir(dir)

	if _, errOut, code := run(t, "add", "GITHUB_TOKEN", "--ref", "op://Dev/GitHub PAT/credential", "--allow", "gh,git", "--note", `say "hi"`); code != 0 {
		t.Fatalf("first add: exit %d: %s", code, errOut)
	}
	if _, errOut, code := run(t, "add", "NVIDIA_API_KEY", "--ref", "bws://dev/NVIDIA_API_KEY", "--ref", "bws://dev/NGC_API_KEY"); code != 0 {
		t.Fatalf("second add: exit %d: %s", code, errOut)
	}
	st, err := os.Stat(cfg)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode: %v %v", st.Mode(), err)
	}
	out, _, code := run(t, "list", "--json")
	if code != 0 || !strings.Contains(out, `"GITHUB_TOKEN"`) || !strings.Contains(out, `"NVIDIA_API_KEY"`) || !strings.Contains(out, `say \"hi\"`) {
		t.Fatalf("after add: %s", out)
	}

	if _, errOut, code := run(t, "add", "GITHUB_TOKEN", "--ref", "env://X"); code != ExitConfig || !strings.Contains(errOut, "already defined") {
		t.Fatalf("duplicate: exit %d: %s", code, errOut)
	}
	pasted := "passess-fake-pasted-0123456789"
	if _, errOut, code := run(t, "add", "OOPS", "--ref", pasted); code != ExitUsage || strings.Contains(errOut, pasted) {
		t.Fatalf("value as ref: exit %d: %s", code, errOut)
	}
	if _, _, code := run(t, "add", "BOTH", "--ref", "env://X", "--keychain"); code != ExitUsage {
		t.Fatalf("--ref with --keychain: exit %d", code)
	}
}

func TestAddKeychainRefusesUnderAHarness(t *testing.T) {
	writeConfig(t, "version = 1\n")
	t.Setenv("CLAUDECODE", "1")
	if _, errOut, code := run(t, "add", "TOKEN", "--keychain"); code != ExitNoPerm || !strings.Contains(errOut, "yourself") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}

func TestDoctor(t *testing.T) {
	noHarness(t) // a person at a terminal gets the credential test; see TestDoctorDoesNotLoadBackendTokensUnderAnAgent
	writeConfig(t, `version = 1
[secrets.A]
ref = "env://PASSESS_TEST_A"
`)
	out, errOut, code := run(t, "doctor", "--json")
	if code != 0 {
		t.Fatalf("healthy config: exit %d: %s %s", code, out, errOut)
	}
	var got doctorOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || !got.Config.OK || got.Secrets != 1 || len(got.Backends) != 1 || !got.Backends[0].OK {
		t.Fatalf("doctor = %+v", got)
	}

	writeConfig(t, "version = 1\n[secrets.B]\nref = \"bws://dev/KEY\"\n")
	t.Setenv("BWS_ACCESS_TOKEN", "")
	out, _, code = run(t, "doctor", "--json")
	if code != 1 || !strings.Contains(out, "bws") {
		t.Fatalf("bws without token: exit %d: %s", code, out)
	}

	t.Setenv("PASSESS_CONFIG", filepath.Join(t.TempDir(), "none.toml"))
	out, _, code = run(t, "doctor")
	if code != 1 || !strings.Contains(out, "no config file") || !strings.Contains(out, "passess add") {
		t.Fatalf("no config: exit %d: %s", code, out)
	}
}

// Each problem the app can fix with a button names the action and what it
// acts on, so Passess.app offers the button instead of a command to copy.
func TestDoctorActions(t *testing.T) {
	problems := func() []problem {
		t.Helper()
		out, _, _ := run(t, "doctor", "--json")
		var got doctorOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatal(err)
		}
		return got.Problems
	}
	t.Setenv("PASSESS_CONFIG", filepath.Join(t.TempDir(), "none.toml"))
	if p := problems(); len(p) != 1 || p[0].Action != "start-config" {
		t.Fatalf("no config: %+v", p)
	}
	writeConfig(t, "version = 1\n[secrets.A\n")
	if p := problems(); len(p) != 1 || p[0].Action != "open-config" || p[0].Target == "" {
		t.Fatalf("broken config: %+v", p)
	}
	t.Setenv("PATH", t.TempDir()) // no op on it
	writeConfig(t, "version = 1\n[secrets.B]\nref = \"op://Dev/item/field\"\n")
	if p := problems(); len(p) != 1 || p[0].Action != "install-tool" || p[0].Target != "op" {
		t.Fatalf("op missing: %+v", p)
	}
}

// check never resolves a secret the calling agent is not connected to: it
// reports it unavailable, and asks for no approval since it returns no value.
// A person at a terminal, an agent the secret is connected to, and a secret
// open to every client see the states as before.
func TestCheckGatesSecretsByClients(t *testing.T) {
	writeConfig(t, `version = 1
[secrets.GATED]
ref = "env://PASSESS_TEST_GATED_TOKEN"
clients = ["codex"]
approve = true
[secrets.OPEN]
ref = "env://PASSESS_TEST_GATED_TOKEN"
[secrets.CODEX_ONLY]
ref = "env://PASSESS_TEST_GATED_TOKEN"
clients = ["codex", "kiro"]
`)
	t.Setenv("PASSESS_TEST_GATED_TOKEN", execValue)
	states := func(t *testing.T) map[string]checked {
		t.Helper()
		out, errOut, _ := run(t, "check", "--json")
		if strings.Contains(out, execValue) || strings.Contains(errOut, execValue) {
			t.Fatal("check printed a value")
		}
		var got checkOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		m := map[string]checked{}
		for _, c := range got.Secrets {
			m[c.Name] = c
		}
		return m
	}

	t.Run("agent not in clients", func(t *testing.T) {
		noHarness(t)
		underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "zsh"}, agent.Proc{Name: "kiro-cli-chat"}, agent.Proc{PID: 1, Name: "launchd"})
		got := states(t)
		if c := got["GATED"]; c.State != stateUnavailable || c.Detail != "not connected to "+detect.Label("kiro") || c.From != "" {
			t.Errorf("GATED = %+v", c)
		}
		if got["OPEN"].State != stateOK || got["CODEX_ONLY"].State != stateOK {
			t.Errorf("secrets open to this agent: %+v", got)
		}
	})
	t.Run("agent by marker", func(t *testing.T) {
		noHarness(t)
		t.Setenv("CLAUDECODE", "1")
		if c := states(t)["GATED"]; c.State != stateUnavailable || !strings.Contains(c.Detail, "not connected to") {
			t.Errorf("GATED = %+v", c)
		}
	})
	t.Run("agent in clients", func(t *testing.T) {
		noHarness(t)
		t.Setenv("CODEX_THREAD_ID", "t")
		if c := states(t)["GATED"]; c.State != stateOK {
			t.Errorf("GATED = %+v", c)
		}
	})
	t.Run("person at a terminal", func(t *testing.T) {
		noHarness(t)
		for n, c := range states(t) {
			if c.State != stateOK {
				t.Errorf("%s = %+v", n, c)
			}
		}
	})
}

// Under a coding agent doctor does not load a backend's bootstrap token: it
// says the credential is configured, not whether it works. A person at a
// terminal still gets the test. Here the token's source is empty, so loading
// it would fail.
func TestDoctorDoesNotLoadBackendTokensUnderAnAgent(t *testing.T) {
	cfgBody := `version = 1
[backends.vault]
address = "https://vault.example.com:8200"
token = "env://PASSESS_TEST_UNSET_BOOT_TOKEN"
[backends.bws]
access_token = "env://PASSESS_TEST_UNSET_BOOT_TOKEN"
[secrets.V]
ref = "vault://secret/app#token"
[secrets.B]
ref = "bws://dev/KEY"
`
	backends := func(t *testing.T) map[string]backendStatus {
		t.Helper()
		out, _, _ := run(t, "doctor", "--json")
		var got doctorOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		m := map[string]backendStatus{}
		for _, b := range got.Backends {
			m[b.Scheme] = b
		}
		return m
	}
	t.Run("agent", func(t *testing.T) {
		noHarness(t)
		writeConfig(t, cfgBody)
		t.Setenv("CLAUDECODE", "1")
		for _, s := range []string{"vault", "bws"} {
			b := backends(t)[s]
			if s == "bws" && strings.Contains(b.Detail, "not installed") {
				continue // no bws on this machine: doctor says so before any credential
			}
			if !b.OK || !strings.Contains(b.Detail, "configured") {
				t.Errorf("%s = %+v", s, b)
			}
		}
	})
	t.Run("agent by ancestor", func(t *testing.T) {
		noHarness(t)
		writeConfig(t, cfgBody)
		underChain(t, agent.Proc{Name: "passess"}, agent.Proc{Name: "kiro-cli-chat"}, agent.Proc{PID: 1, Name: "launchd"})
		if b := backends(t)["vault"]; !b.OK || !strings.Contains(b.Detail, "configured") {
			t.Errorf("vault = %+v", b)
		}
	})
	t.Run("person at a terminal", func(t *testing.T) {
		noHarness(t)
		writeConfig(t, cfgBody)
		for _, s := range []string{"vault", "bws"} {
			if b := backends(t)[s]; b.OK {
				t.Errorf("%s = %+v: a person gets the real test", s, b)
			}
		}
	})
}
