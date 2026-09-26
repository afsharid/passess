package scan

import (
	"strings"
	"testing"
)

// BenchmarkLoadAndCheckPrompt is what a prompt hook pays: parse the rule set,
// then check a few lines of ordinary text.
func BenchmarkLoadAndCheckPrompt(b *testing.B) {
	prompt := strings.Repeat("Please refactor the handler in server.go and add a test for the retry path.\n", 5)
	for b.Loop() {
		rs, err := DefaultRules()
		if err != nil {
			b.Fatal(err)
		}
		for _, line := range strings.Split(prompt, "\n") {
			rs.Line("prompt", line)
		}
	}
}
