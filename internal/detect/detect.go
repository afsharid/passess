// Package detect recognizes the AI harness a process runs under from the
// markers harnesses put in their children's environment.
//
// Whoever controls the environment can remove a marker, so detection is only
// ever used to add protection (or to label a record), never to grant anything.
package detect

var markers = []struct {
	harness string
	vars    []string
}{
	{"claude-code", []string{"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_PROJECT_DIR"}},
	{"codex", []string{"CODEX_THREAD_ID", "CODEX_SANDBOX", "CODEX_CI"}},
	{"cursor", []string{"CURSOR_TRACE_ID", "CURSOR_AGENT", "CURSOR_CLI"}},
	{"gemini-cli", []string{"GEMINI_CLI", "GEMINI_PROJECT_DIR"}},
	{"opencode", []string{"OPENCODE", "OPENCODE_PID", "OPENCODE_CLIENT", "OPENCODE_TERMINAL"}},
	{"antigravity", []string{"ANTIGRAVITY_CLI_ALIAS"}},
	{"zed", []string{"ZED_SESSION_ID"}},
}

// Harness returns the harness name, or "" when no marker is present.
func Harness(getenv func(string) string) string {
	for _, m := range markers {
		for _, v := range m.vars {
			if getenv(v) != "" {
				return m.harness
			}
		}
	}
	return ""
}

// programs maps the process names of harness executables, as the kernel
// keeps them, to harness names. Editors whose terminals people also type in
// (Zed, VS Code) are left out: their process says nothing about who typed.
var programs = map[string]string{
	"claude": "claude-code", "codex": "codex", "opencode": "opencode", "opencode.exe": "opencode",
	"kiro-cli": "kiro", "kiro-cli-chat": "kiro", "agy": "antigravity", "cursor-agent": "cursor", "gemini": "gemini-cli",
}

// Program returns the harness whose executable has this process name, or "".
func Program(name string) string { return programs[name] }

// OwnPrefix is the prefix of the variables a harness sets for its own use
// (CLAUDE_CODE_MESSAGING_TOKEN under Claude Code), or "". Variables the user
// sets for a harness, such as GEMINI_API_KEY, are not the harness's own.
func OwnPrefix(harness string) string {
	return map[string]string{
		"claude-code": "CLAUDE_CODE_", "codex": "CODEX_", "cursor": "CURSOR_", "opencode": "OPENCODE_",
		"antigravity": "ANTIGRAVITY_", "zed": "ZED_",
	}[harness]
}
