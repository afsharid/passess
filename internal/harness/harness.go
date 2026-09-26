// Package harness reads and changes how AI harnesses start MCP servers and what
// instructions they give the model.
//
// Reading is done by parsing the harness's own config; writing is delegated to
// the harness's CLI (`claude mcp add`, `codex mcp add`), which owns the file
// format. Entries passess writes hold no secret — only `passess mcp-exec NAME`
// — so passing them on a command line exposes nothing.
package harness

import (
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Entry is an MCP server as a harness config has it.
type Entry struct {
	Name       string   `json:"name"`
	Command    string   `json:"command,omitempty"`
	Args       []string `json:"args,omitempty"`
	URL        string   `json:"url,omitempty"`
	EnvKeys    []string `json:"env_keys,omitempty"`
	HeaderKeys []string `json:"header_keys,omitempty"`
	// Leaks names env variables and headers whose values look like
	// credentials sitting in the config file in clear. Values are never kept.
	Leaks []string `json:"leaks,omitempty"`
}

// ManagedBy reports whether the entry runs `passess mcp-exec <its name>`, with
// passess either named so or being self, the binary doing the asking.
func (e Entry) ManagedBy(self string) bool {
	if len(e.Args) != 2 || e.Args[0] != "mcp-exec" || e.Args[1] != e.Name {
		return false
	}
	return filepath.Base(e.Command) == "passess" || (self != "" && e.Command == self)
}

// Adapter is one harness.
type Adapter interface {
	ID() string    // short name used on the command line: claude, codex
	Label() string // human name
	// Installed reports whether the harness is present at all.
	Installed() bool
	ConfigPath() string
	// Entries parses the MCP servers from the harness config.
	Entries() ([]Entry, error)
	// AddCommand and RemoveCommand return the harness CLI invocation.
	AddCommand(name string, argv []string) []string
	RemoveCommand(name string) []string
	InstructionsPath() string
}

var tokenPrefixes = regexp.MustCompile(`(?i)^(bearer\s+|token\s+)?(gh[pousr]_|github_pat_|glpat-|sk-|xox[abprs]-|AKIA|AIza|ya29\.|npm_|pypi-|hf_|dop_v1_|shpat_|sq0atp-)`)

// looksLikeSecret is a conservative test for a credential stored in clear.
func looksLikeSecret(v string) bool {
	v = strings.TrimSpace(v)
	if tokenPrefixes.MatchString(v) && len(v) >= 12 {
		return true
	}
	lower := strings.ToLower(v)
	for _, scheme := range []string{"bearer ", "token ", "basic "} {
		if strings.HasPrefix(lower, scheme) {
			v = strings.TrimSpace(v[len(scheme):])
			break
		}
	}
	if len(v) < 20 || strings.ContainsAny(v, " /\\") || strings.HasPrefix(v, "$") || strings.Contains(v, "${") {
		return false
	}
	return entropy(v) >= 3.5
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

// keysAndLeaks returns the sorted keys of m and those whose values look like credentials.
func keysAndLeaks(m map[string]any, prefix string) (keys, leaks []string) {
	for k, v := range m {
		keys = append(keys, k)
		if s, ok := v.(string); ok && looksLikeSecret(s) {
			leaks = append(leaks, prefix+k)
		}
	}
	sort.Strings(keys)
	sort.Strings(leaks)
	return keys, leaks
}

func stringsOf(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
