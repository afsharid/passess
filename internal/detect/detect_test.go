package detect

import (
	"slices"
	"testing"
)

// Every harness passess can detect is one a secret can be connected to, so
// a clients list can name whatever a refusal names.
func TestAgentsCoverEveryDetectedHarness(t *testing.T) {
	var names []string
	for _, m := range markers {
		names = append(names, m.harness)
	}
	for _, h := range programs {
		names = append(names, h)
	}
	for _, n := range names {
		if !IsAgent(n) {
			t.Errorf("%s is detected but missing from Agents", n)
		}
	}
	for _, a := range Agents {
		if !slices.Contains(names, a.ID) {
			t.Errorf("%s is in Agents but never detected", a.ID)
		}
		if Label(a.ID) == a.ID {
			t.Errorf("%s has no label", a.ID)
		}
	}
}

func TestHarnessesNamesEveryMarker(t *testing.T) {
	env := map[string]string{"CLAUDECODE": "1", "CODEX_THREAD_ID": "t"}
	got := Harnesses(func(k string) string { return env[k] })
	if !slices.Equal(got, []string{"claude-code", "codex"}) {
		t.Fatalf("got %v", got)
	}
}
