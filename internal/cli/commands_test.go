package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if len(got.Secrets) != 2 || got.Secrets[0].Name != "DB_URL" || !got.Secrets[0].Project || got.Secrets[1].Project {
		t.Fatalf("secrets = %+v", got.Secrets)
	}
	if strings.Join(got.Secrets[0].Backends, ",") != "env,keychain" || strings.Join(got.Secrets[1].Allow, ",") != "gh,git" {
		t.Fatalf("details = %+v", got.Secrets)
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
ref = "op://Dev/item/field"
`)
	t.Setenv("PASSESS_TEST_PRESENT_TOKEN", execValue)
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
