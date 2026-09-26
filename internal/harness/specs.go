package harness

// Entry shapes, fields in the order each harness documents them.
type stdioEntry struct {
	Type    string   `json:"type,omitempty"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type openCodeEntry struct {
	Type    string   `json:"type"`
	Command []string `json:"command"` // program and arguments in one array
	Enabled bool     `json:"enabled"`
}

func stdio(typ string) func([]string) any {
	return func(argv []string) any { return stdioEntry{Type: typ, Command: argv[0], Args: argv[1:]} }
}

// JSONSpecs are the harnesses passess reaches through a JSON or JSONC file,
// for the given GOOS. Sources and how each fact was checked are in
// docs/HARNESS-MATRIX.md.
func JSONSpecs(goos string) []JSONSpec {
	appSupport := func(mac, linux string) []string { // per-OS app config locations
		switch goos {
		case "darwin":
			return []string{"Library/Application Support/" + mac}
		case "linux":
			if linux != "" {
				return []string{"$XDG/" + linux}
			}
		}
		return nil
	}
	return []JSONSpec{
		{
			ID: "opencode", Label: "OpenCode",
			Paths:  []string{"$XDG/opencode/opencode.json", "$XDG/opencode/opencode.jsonc"},
			Create: true, Servers: []string{"mcp"},
			Entry: func(argv []string) any {
				return openCodeEntry{Type: "local", Command: argv, Enabled: true}
			},
			Instructions: "$XDG/opencode/AGENTS.md",
		},
		{
			// kiro-cli can add servers, but only when signed in: passess edits
			// the file so it works, and can be tested, either way.
			ID: "kiro", Label: "Kiro",
			Paths: []string{".kiro/settings/mcp.json"}, Create: true, Servers: []string{"mcpServers"},
			Entry: stdio(""), Instructions: ".kiro/steering/passess.md",
		},
		{
			// agy writes the file itself; ~/.gemini/antigravity/mcp_config.json
			// is a symlink to the same file on current installs.
			ID: "antigravity", Label: "Antigravity",
			Paths: []string{".gemini/config/mcp_config.json", ".gemini/antigravity/mcp_config.json"},
			Bins:  []string{"agy"}, Servers: []string{"mcpServers"},
			AddArgv: func(name string, argv []string) []string {
				return append([]string{"agy", "mcp", "add", name}, argv...)
			},
			RemoveArgv:   func(name string) []string { return []string{"agy", "mcp", "remove", name} },
			Instructions: ".gemini/config/rules/passess.md",
		},
		{
			// settings.json is strict JSON; the editor keeps it so.
			ID: "gemini", Label: "Gemini CLI",
			Paths: []string{".gemini/settings.json"}, Create: true, Bins: []string{"gemini"},
			Servers: []string{"mcpServers"}, Entry: stdio(""), Instructions: ".gemini/GEMINI.md",
		},
		{
			ID: "cursor", Label: "Cursor",
			Paths: []string{".cursor/mcp.json"}, Create: true, Servers: []string{"mcpServers"},
			Entry: stdio("stdio"),
		},
		{
			// The user-level path is inferred from where VS Code keeps
			// settings.json, so passess only edits a file that exists.
			ID: "vscode", Label: "VS Code",
			Paths:   appSupport("Code/User/mcp.json", "Code/User/mcp.json"),
			Servers: []string{"servers"}, Entry: stdio("stdio"),
		},
		{
			// Windsurf's docs now point at ~/.config/devin; older installs
			// use ~/.codeium/windsurf. Only an existing file is edited.
			ID: "windsurf", Label: "Windsurf",
			Paths:   []string{".codeium/windsurf/mcp_config.json", "$XDG/devin/mcp_config.json"},
			Servers: []string{"mcpServers"}, Entry: stdio(""),
		},
		{
			ID: "zed", Label: "Zed",
			Paths: []string{"$XDG/zed/settings.json"}, Servers: []string{"context_servers"},
			Entry: stdio(""), Instructions: "$XDG/zed/AGENTS.md",
		},
		{
			// Claude Desktop runs on macOS and Windows only.
			ID: "claude-desktop", Label: "Claude Desktop",
			Paths:  appSupport("Claude/claude_desktop_config.json", ""),
			Create: true, Servers: []string{"mcpServers"}, Entry: stdio(""),
		},
	}
}
