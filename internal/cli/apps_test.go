package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDSH(t *testing.T) {
	dir := setupDir(t)
	noHarness(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("DSH_HOME", "")
	body := `version = 1
[secrets.NAMED]
ref     = "env://PASSESS_TEST_X_TOKEN"
clients = ["dsh"]
[secrets.EVERY]
ref = "env://PASSESS_TEST_X_TOKEN"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(home, ".dsh", "profiles", "desktop")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	patch := filepath.Join(profile, "cordis.patch.yml")
	user := "- id: llm-pi-ai\n  config:\n    a:\n      apiKeyEnv: NAMED\n    b:\n      apiKeyEnv: EVERY\n    c:\n      apiKeyEnv: NOWHERE\n"
	if err := os.WriteFile(patch, []byte(user), 0o600); err != nil {
		t.Fatal(err)
	}

	status := func() (harnessOutput, int) {
		t.Helper()
		out, errOut, code := run(t, "status", "dsh", "--json")
		var got harnessOutput
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("status: %v; %s %s", err, out, errOut)
		}
		return got, code
	}
	got, code := status()
	if code != 1 || len(got.Harnesses) != 0 || len(got.Apps) != 1 || got.Apps[0].Plugin != "missing" {
		t.Fatalf("before install: exit %d, %+v", code, got)
	}
	keys := map[string]string{}
	for _, k := range got.Apps[0].Keys {
		keys[k.Name] = k.State
	}
	if keys["NAMED"] != keyConnected || keys["EVERY"] != keyEveryAgent || keys["NOWHERE"] != keyUndefined {
		t.Fatalf("key states: %v", keys)
	}

	out, _, code := run(t, "install", "dsh")
	if code != 0 || !strings.Contains(out, "would write the plugin") || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run: exit %d, %s", code, out)
	}
	if data, _ := os.ReadFile(patch); string(data) != user {
		t.Fatal("a dry run changed the patch")
	}

	if out, errOut, code := run(t, "install", "dsh", "--apply"); code != 0 || !strings.Contains(out, "backup:") {
		t.Fatalf("install: exit %d, %s %s", code, out, errOut)
	}
	if got, code := status(); code != 0 || got.Apps[0].Plugin != "ok" {
		t.Fatalf("after install: exit %d, %+v", code, got.Apps[0])
	}
	if data, _ := os.ReadFile(patch); !strings.HasPrefix(string(data), user) {
		t.Fatalf("install must keep the user's rows:\n%s", data)
	}

	if out, errOut, code := run(t, "uninstall", "dsh", "--apply"); code != 0 {
		t.Fatalf("uninstall: exit %d, %s %s", code, out, errOut)
	}
	if data, _ := os.ReadFile(patch); string(data) != user {
		t.Fatalf("uninstall must leave the user's rows only:\n%s", data)
	}
}
