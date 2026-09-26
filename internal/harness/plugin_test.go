package harness

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/afsharid/passess/internal/jsonedit"
)

// The Claude Code plugin registers what `passess install` does, with passess
// found on PATH.
func TestClaudePluginMatchesInstall(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "plugins", "claude", "hooks", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plugin struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if err := jsonedit.Decode(data, &plugin); err != nil {
		t.Fatal(err)
	}
	spec := HookSpecs()[0]
	if spec.ID != "claude" || len(plugin.Hooks) != len(spec.Events) {
		t.Fatalf("plugin events = %v", plugin.Hooks)
	}
	for _, e := range spec.Events {
		g := plugin.Hooks[e.Name]
		if len(g) != 1 || g[0].Matcher != e.Matcher || len(g[0].Hooks) != 1 || g[0].Hooks[0].Command != "passess hook claude "+e.Name {
			t.Errorf("plugin %s = %+v", e.Name, g)
		}
	}
}
