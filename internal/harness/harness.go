// Package harness reads and changes how AI harnesses start MCP servers and what
// instructions they give the model.
//
// Reading is done by parsing the harness's own config; writing is delegated to
// the harness's CLI (`claude mcp add`, `codex mcp add`), which owns the file
// format. Entries passess writes hold no secret — only `passess mcp-exec NAME`
// — so passing them on a command line exposes nothing.
package harness

import (
	"path/filepath"
	"sort"

	"github.com/afsharid/passess/internal/policy"
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
	// Raw returns one entry with its values, for migration.
	Raw(name string) (Raw, bool, error)
	// AddCommand and RemoveCommand return the harness CLI invocation.
	AddCommand(name string, argv []string) []string
	RemoveCommand(name string) []string
	InstructionsPath() string
}

// Raw is an entry with its values, read only by `passess migrate` to move them
// into a vault. It is never printed or written anywhere but the vault.
type Raw struct {
	Command string
	Args    []string
	URL     string
	Env     map[string]string
	Headers map[string]string
}

func rawFrom(s map[string]any, headerKey string) Raw {
	r := Raw{Env: map[string]string{}, Headers: map[string]string{}}
	r.Command, _ = s["command"].(string)
	r.Args = stringsOf(s["args"])
	r.URL, _ = s["url"].(string)
	for dst, key := range map[*map[string]string]string{&r.Env: "env", &r.Headers: headerKey} {
		m, _ := s[key].(map[string]any)
		for k, v := range m {
			if str, ok := v.(string); ok {
				(*dst)[k] = str
			}
		}
	}
	return r
}

// keysAndLeaks returns the sorted keys of m and those whose values look like credentials.
func keysAndLeaks(m map[string]any, prefix string) (keys, leaks []string) {
	for k, v := range m {
		keys = append(keys, k)
		if s, ok := v.(string); ok && policy.LooksLikeSecret(s) {
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
