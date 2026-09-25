package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupProfiles(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	body := `version = 1
[secrets.X]
ref = "env://PASSESS_TEST_X_TOKEN"
[secrets.OPTIONAL]
ref = "env://PASSESS_TEST_NEVER_SET"
[secrets.GH_ONLY]
ref   = "env://PASSESS_TEST_X_TOKEN"
allow = ["gh"]

[profiles.svc]
secrets  = ["X", "OPTIONAL"]
required = ["X"]
allow    = ["sh"]
inherit  = ["PASSESS_TEST_INHERIT"]
env      = { PLAIN_HOME = "~/state", MODE = "test" }

[profiles.missing]
secrets  = ["OPTIONAL"]
required = ["OPTIONAL"]
allow    = ["sh"]

[profiles.narrow]
secrets = ["GH_ONLY"]
allow   = ["sh"]
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", cfg)
	t.Setenv("PASSESS_TEST_X_TOKEN", execValue)
	t.Setenv("PASSESS_TEST_INHERIT", "inherited")
	t.Setenv("PASSESS_TEST_NOISE", "should-not-pass")
	t.Setenv("UNRELATED_API_KEY", "passess-fake-unrelated-0123456789")
	t.Chdir(dir)
	return dir
}

func TestRunBuildsTheProfileEnvironment(t *testing.T) {
	setupProfiles(t)
	out, errOut, code := run(t, "run", "svc", "--", "sh", "-c", "env")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	home := os.Getenv("HOME")
	for _, want := range []string{"X=[REDACTED:X]", "PASSESS_TEST_INHERIT=inherited", "PLAIN_HOME=" + home + "/state", "MODE=test", "PATH="} {
		if !strings.Contains(out, want) {
			t.Errorf("environment lacks %q", want)
		}
	}
	for _, gone := range []string{"PASSESS_TEST_NOISE", "UNRELATED_API_KEY", "PASSESS_TEST_X_TOKEN", "OPTIONAL=", execValue} {
		if strings.Contains(out, gone) {
			t.Errorf("environment has %q", gone)
		}
	}
}

func TestRunRefusals(t *testing.T) {
	setupProfiles(t)
	if _, errOut, code := run(t, "run", "svc", "--", "ls"); code != ExitNoPerm || !strings.Contains(errOut, "profiles.svc.allow") {
		t.Fatalf("program outside the profile: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run(t, "run", "narrow", "--", "sh", "-c", "true"); code != ExitNoPerm || !strings.Contains(errOut, "GH_ONLY") {
		t.Fatalf("secret's own allow list ignored: exit %d, %q", code, errOut)
	}
	if _, errOut, code := run(t, "run", "missing", "--", "sh", "-c", "true"); code != ExitConfig || !strings.Contains(errOut, "OPTIONAL could not be resolved") {
		t.Fatalf("required secret missing: exit %d, %q", code, errOut)
	}
	if _, _, code := run(t, "run", "nope", "--", "sh"); code != ExitConfig {
		t.Fatalf("unknown profile: exit %d", code)
	}
	if _, _, code := run(t, "run", "svc"); code != ExitUsage {
		t.Fatalf("no command: exit %d", code)
	}
}
