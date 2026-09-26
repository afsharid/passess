package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
