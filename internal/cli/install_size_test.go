package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/harness"
)

// editHooks and editConfig refuse a harness config over the size cap, by name,
// and leave the file as it was.
func TestEditRefusesHugeConfig(t *testing.T) {
	big := []byte("{}" + strings.Repeat(" ", harness.MaxConfigSize))
	write := func(path string) {
		if err := os.WriteFile(path, big, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	home := t.TempDir()
	h := harness.Hooks{Spec: harness.HookSpecs()[0], Home: home}
	if err := os.MkdirAll(filepath.Dir(h.File()), 0o700); err != nil {
		t.Fatal(err)
	}
	write(h.File())
	if err := editHooks(h, "/opt/bin/passess", true); err == nil || !strings.Contains(err.Error(), h.File()) {
		t.Errorf("editHooks over the cap: %v", err)
	}
	spec := harness.JSONSpecs("darwin")[0]
	j := harness.JSONFile{Spec: spec, Home: home}
	if err := os.MkdirAll(filepath.Dir(j.ConfigPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	write(j.ConfigPath())
	err := editConfig(j, j, []harness.Action{{Kind: "add", Server: "x", Argv: []string{"/opt/bin/passess", "mcp-exec", "x"}}})
	if err == nil || !strings.Contains(err.Error(), j.ConfigPath()) {
		t.Errorf("editConfig over the cap: %v", err)
	}
	if st, err := os.Stat(j.ConfigPath()); err != nil || st.Size() != int64(len(big)) {
		t.Errorf("config changed: %v", err)
	}
}
