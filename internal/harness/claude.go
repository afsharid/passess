package harness

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// Claude is Claude Code. Its user-scope MCP servers live in ~/.claude.json,
// a file Claude Code rewrites constantly, so passess only reads it and makes
// changes through `claude mcp`.
type Claude struct {
	Home string
}

func (Claude) ID() string    { return "claude" }
func (Claude) Label() string { return "Claude Code" }

func (c Claude) ConfigPath() string       { return filepath.Join(c.Home, ".claude.json") }
func (c Claude) InstructionsPath() string { return filepath.Join(c.Home, ".claude", "CLAUDE.md") }

func (c Claude) Installed() bool {
	if _, err := exec.LookPath("claude"); err == nil {
		return true
	}
	_, err := os.Stat(c.ConfigPath())
	return err == nil
}

func (c Claude) Entries() ([]Entry, error) {
	data, err := os.ReadFile(c.ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		MCPServers map[string]map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.New(c.ConfigPath() + " is not valid JSON")
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
		headers, _ := s["headers"].(map[string]any)
		e.HeaderKeys, leaks = keysAndLeaks(headers, "headers.")
		e.Leaks = append(e.Leaks, leaks...)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (Claude) AddCommand(name string, argv []string) []string {
	return append([]string{"claude", "mcp", "add", "--scope", "user", name, "--"}, argv...)
}

func (Claude) RemoveCommand(name string) []string {
	return []string{"claude", "mcp", "remove", "--scope", "user", name}
}
