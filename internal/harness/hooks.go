package harness

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/afsharid/passess/internal/jsonedit"
)

// Hook styles: how a harness lays out its hook config.
const (
	// HookGroups is Claude Code's layout, which Codex and Gemini CLI share:
	// {"hooks": {"Event": [{"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}]}}
	HookGroups = "groups"
	// HookCursor is {"version": 1, "hooks": {"event": [{"command": "..."}]}}.
	HookCursor = "cursor"
	// HookNamed is Antigravity's: {"<hook name>": {"Event": [groups as above]}}.
	HookNamed = "named"
	// HookPlugin is a file passess owns outright (OpenCode's plugin).
	HookPlugin = "plugin"
)

// HookEvent is one event passess handles, and which tools it matches.
type HookEvent struct {
	Name    string
	Matcher string // "" for events without one
}

// HookSpec says where a harness reads hooks and what passess registers.
type HookSpec struct {
	ID      string // the adapter's ID
	Harness string // the name `passess hook` knows it by
	Path    string // HOME-relative, or "$XDG/…"
	Style   string
	Events  []HookEvent
	// Create allows writing a missing file, into a directory that exists.
	Create bool
	// Note is shown after install: what the user must still do.
	Note string
}

//go:embed hooks/opencode.js
var openCodePlugin string

// HookSpecs are the harnesses passess registers its hook handler with.
// Kiro keeps hooks inside agent profiles and is left to the user.
func HookSpecs() []HookSpec {
	tools := "Bash|Read|Grep|Write|Edit|MultiEdit|NotebookRead|NotebookEdit"
	return []HookSpec{
		{ID: "claude", Harness: "claude", Path: ".claude/settings.json", Style: HookGroups, Create: true, Events: []HookEvent{
			{"PreToolUse", tools}, {"PostToolUse", "*"}, {"UserPromptSubmit", ""}, {"SessionStart", ""}},
			Note: "Claude Code reads hooks when a session starts: restart open sessions, or review the change in /hooks."},
		{ID: "codex", Harness: "codex", Path: ".codex/hooks.json", Style: HookGroups, Create: true, Events: []HookEvent{
			{"PreToolUse", ".*"}, {"UserPromptSubmit", ""}, {"SessionStart", ""}},
			Note: "Codex runs new hooks only after you trust them: open Codex and review them with /hooks."},
		{ID: "gemini", Harness: "gemini", Path: ".gemini/settings.json", Style: HookGroups, Create: true, Events: []HookEvent{
			{"BeforeTool", "run_shell_command|read_file|read_many_files|write_file|replace"}, {"AfterTool", ".*"},
			{"BeforeAgent", ""}, {"SessionStart", ""}}},
		{ID: "cursor", Harness: "cursor", Path: ".cursor/hooks.json", Style: HookCursor, Create: true, Events: []HookEvent{
			{"beforeShellExecution", ""}, {"beforeReadFile", ""}, {"beforeSubmitPrompt", ""}, {"sessionStart", ""}}},
		{ID: "antigravity", Harness: "antigravity", Path: ".gemini/config/hooks.json", Style: HookNamed, Create: true, Events: []HookEvent{
			{"PreToolUse", "run_command|view_file|view_file_outline|view_code_item|grep_search|write_to_file|replace_file_content|multi_replace_file_content"}}},
		{ID: "opencode", Harness: "opencode", Path: "$XDG/opencode/plugins/passess.js", Style: HookPlugin, Create: true},
	}
}

// Hooks is a HookSpec on this machine.
type Hooks struct {
	Spec       HookSpec
	Home       string
	ConfigHome string
}

func (h Hooks) Path() string {
	return JSONFile{Home: h.Home, ConfigHome: h.ConfigHome}.abs(h.Spec.Path)
}

// File is the file passess edits: a symlink's target.
func (h Hooks) File() string {
	if real, err := filepath.EvalSymlinks(h.Path()); err == nil {
		return real
	}
	return h.Path()
}

func command(self, harness, event string) string {
	return shellWord(self) + " hook " + harness + " " + event
}

func shellWord(s string) string {
	if strings.ContainsAny(s, " \t'\"$`\\") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// IsPassessCommand reports whether a hook command runs `passess hook`, with
// passess named so or being self, the binary doing the asking.
func IsPassessCommand(cmd, self string) bool {
	cmd = strings.TrimSpace(cmd)
	var first, rest string
	if cmd != "" && (cmd[0] == '\'' || cmd[0] == '"') { // a quoted program path
		end := strings.IndexByte(cmd[1:], cmd[0])
		if end < 0 {
			return false
		}
		first, rest = cmd[1:1+end], cmd[2+end:]
	} else {
		first, rest, _ = strings.Cut(cmd, " ")
	}
	f := strings.Fields(rest)
	return (filepath.Base(first) == "passess" || (self != "" && first == self)) && len(f) > 0 && f[0] == "hook"
}

type hookHandler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type hookGroup struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []hookHandler `json:"hooks"`
}

func (h Hooks) group(self string, e HookEvent) any {
	handler := hookHandler{Type: "command", Command: command(self, h.Spec.Harness, e.Name)}
	switch h.Spec.Style {
	case HookCursor:
		return handler
	case HookNamed:
		handler.Timeout = 10 // seconds; Antigravity's default is 30
	}
	return hookGroup{Matcher: e.Matcher, Hooks: []hookHandler{handler}}
}

// commandsIn lists the hook commands in one decoded element (a group or a
// Cursor handler).
func commandsIn(v any) []string {
	m, _ := v.(map[string]any)
	if c, ok := m["command"].(string); ok {
		return []string{c}
	}
	var out []string
	hooks, _ := m["hooks"].([]any)
	for _, h := range hooks {
		if hm, _ := h.(map[string]any); hm != nil {
			if c, ok := hm["command"].(string); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

func isPassessElement(self string) func(any) bool {
	return func(v any) bool {
		return slices.ContainsFunc(commandsIn(v), func(c string) bool { return IsPassessCommand(c, self) })
	}
}

func (h Hooks) eventsPath(event string) []string {
	if h.Spec.Style == HookNamed {
		return []string{"passess", event}
	}
	return []string{"hooks", event}
}

// State is ok when every event runs `self hook …` exactly once, drift when
// passess hooks are there but for another binary or events, missing when
// there are none.
func (h Hooks) State(self string) (string, error) {
	data, err := os.ReadFile(h.File())
	if errors.Is(err, os.ErrNotExist) {
		return StateMissing, nil
	}
	if err != nil {
		return "", err
	}
	defer clear(data)
	if h.Spec.Style == HookPlugin {
		if string(data) == h.plugin(self) {
			return StateOK, nil
		}
		return StateDrift, nil
	}
	var doc map[string]any
	if err := jsonedit.Decode(data, &doc); err != nil {
		return "", fmt.Errorf("%s is not valid JSON", h.File())
	}
	found, exact := 0, 0
	for _, e := range h.Spec.Events {
		var at any = doc
		for _, k := range h.eventsPath(e.Name) {
			m, _ := at.(map[string]any)
			at = m[k]
		}
		list, _ := at.([]any)
		mine := 0
		for _, el := range list {
			if isPassessElement(self)(el) {
				mine++
				found++
				if slices.Contains(commandsIn(el), command(self, h.Spec.Harness, e.Name)) {
					exact++
				}
			}
		}
		if mine > 1 {
			return StateDrift, nil
		}
	}
	switch {
	case found == 0:
		return StateMissing, nil
	case exact == len(h.Spec.Events) && found == exact:
		return StateOK, nil
	}
	return StateDrift, nil
}

func (h Hooks) plugin(self string) string {
	return strings.ReplaceAll(openCodePlugin, "__PASSESS__", strings.ReplaceAll(self, `\`, `\\`))
}

// Edit returns the hook config with passess's handlers for self installed,
// or without any passess handler when install is false. A nil result with no
// error means the file should be removed (a plugin passess owns).
func (h Hooks) Edit(data []byte, self string, install bool) ([]byte, error) {
	if h.Spec.Style == HookPlugin {
		if install {
			return []byte(h.plugin(self)), nil
		}
		return nil, nil
	}
	var err error
	if h.Spec.Style == HookNamed {
		if !install {
			return jsonedit.Delete(data, nil, "passess")
		}
		events := map[string]any{}
		for _, e := range h.Spec.Events {
			events[e.Name] = []any{h.group(self, e)}
		}
		return jsonedit.Set(data, nil, "passess", events)
	}
	if h.Spec.Style == HookCursor && install && len(strings.TrimSpace(string(data))) == 0 {
		data = []byte("{\n  \"version\": 1\n}\n")
	}
	emptied := false
	for _, e := range h.Spec.Events {
		before := data
		if data, err = jsonedit.RemoveWhere(data, h.eventsPath(e.Name), isPassessElement(self)); err != nil {
			return nil, err
		}
		if install {
			if data, err = jsonedit.Append(data, h.eventsPath(e.Name), h.group(self, e)); err != nil {
				return nil, err
			}
			continue
		}
		// An event list that only held passess's handler goes with it, so
		// uninstall gives back the file as it was.
		if !bytes.Equal(before, data) && sizeAt(data, h.eventsPath(e.Name)) == 0 {
			if data, err = jsonedit.Delete(data, []string{"hooks"}, e.Name); err != nil {
				return nil, err
			}
			emptied = true
		}
	}
	if emptied && sizeAt(data, []string{"hooks"}) == 0 {
		if data, err = jsonedit.Delete(data, nil, "hooks"); err != nil {
			return nil, err
		}
	}
	if !install && onlyVersion(data) {
		return nil, nil // nothing left but what passess wrote: the file goes
	}
	return data, nil
}

// onlyVersion reports a document with no members, or only Cursor's version.
func onlyVersion(data []byte) bool {
	var doc map[string]any
	if jsonedit.Decode(data, &doc) != nil {
		return false
	}
	_, v := doc["version"]
	return len(doc) == 0 || (len(doc) == 1 && v)
}

// sizeAt is the number of members or elements at path, or -1.
func sizeAt(data []byte, path []string) int {
	var doc any
	if jsonedit.Decode(data, &doc) != nil {
		return -1
	}
	for _, k := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			return -1
		}
		if doc, ok = m[k]; !ok {
			return -1
		}
	}
	switch v := doc.(type) {
	case map[string]any:
		return len(v)
	case []any:
		return len(v)
	}
	return -1
}

// Installable reports whether passess may write the hook file: it exists,
// or may be created in a directory that exists.
func (h Hooks) Installable() bool {
	if _, err := os.Stat(h.File()); err == nil {
		return true
	}
	if !h.Spec.Create {
		return false
	}
	dir := filepath.Dir(h.Path())
	if h.Spec.Style == HookPlugin {
		dir = filepath.Dir(dir) // plugins/ may be new; the opencode directory must not be
	}
	st, err := os.Stat(dir)
	return err == nil && st.IsDir()
}
