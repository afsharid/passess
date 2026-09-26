package harness

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"

	"github.com/pelletier/go-toml/v2"
)

// Codex is the OpenAI Codex CLI. MCP servers live in $CODEX_HOME/config.toml
// (default ~/.codex); passess reads the file and changes it through
// `codex mcp`, which keeps the user's other tables and comments intact.
type Codex struct {
	Home      string
	CodexHome string // $CODEX_HOME if set
}

func (Codex) ID() string    { return "codex" }
func (Codex) Label() string { return "Codex" }

func (c Codex) dir() string {
	if c.CodexHome != "" {
		return c.CodexHome
	}
	return filepath.Join(c.Home, ".codex")
}

func (c Codex) ConfigPath() string       { return filepath.Join(c.dir(), "config.toml") }
func (c Codex) InstructionsPath() string { return filepath.Join(c.dir(), "AGENTS.md") }

func (c Codex) Installed() bool {
	if _, err := exec.LookPath("codex"); err == nil {
		return true
	}
	_, err := os.Stat(c.dir())
	return err == nil
}

func (c Codex) Entries() ([]Entry, error) {
	data, err := os.ReadFile(c.ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]map[string]any `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(data, &doc); err != nil {
		return nil, errors.New(c.ConfigPath() + " is not valid TOML")
	}
	var out []Entry
	for name, s := range doc.MCPServers {
		e := Entry{Name: name}
		e.Command, _ = s["command"].(string)
		e.Args = stringsOf(s["args"])
		e.URL, _ = s["url"].(string)
		env, _ := s["env"].(map[string]any)
		var leaks []string
		e.EnvKeys, leaks = keysAndLeaks(env, "env.")
		e.Leaks = append(e.Leaks, leaks...)
		headers, _ := s["http_headers"].(map[string]any)
		e.HeaderKeys, leaks = keysAndLeaks(headers, "http_headers.")
		e.Leaks = append(e.Leaks, leaks...)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (Codex) AddCommand(name string, argv []string) []string {
	return append([]string{"codex", "mcp", "add", name, "--"}, argv...)
}

func (Codex) RemoveCommand(name string) []string {
	return []string{"codex", "mcp", "remove", name}
}
