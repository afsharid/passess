package hook

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Reply is what a hook process gives back to its harness.
type Reply struct {
	Stdout, Stderr []byte
	Exit           int
}

// Adapter reads one harness's hook payload and writes its reply.
type Adapter interface {
	// Parse turns the payload of the named event into an Event.
	Parse(event string, payload []byte, getenv func(string) string) (Event, error)
	// Render is what the harness expects back.
	Render(ev Event, v Verdict) Reply
}

// Adapters by the name used in `passess hook NAME EVENT`.
var Adapters = map[string]Adapter{
	"claude":      claude{rewritesOutput: true},
	"codex":       claude{}, // same protocol, no documented way to rewrite a result
	"gemini":      gemini{},
	"cursor":      cursor{},
	"opencode":    opencode{},
	"kiro":        kiro{},
	"antigravity": antigravity{},
}

func jsonReply(v any) Reply {
	b, _ := json.Marshal(v)
	return Reply{Stdout: append(b, '\n')}
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// shellCommand reads a command given as a string or as an argv array such as
// ["bash", "-lc", "…"].
func shellCommand(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		var parts []string
		for _, p := range c {
			s, _ := p.(string)
			parts = append(parts, s)
		}
		if len(parts) >= 3 && strings.HasPrefix(parts[1], "-") && strings.Contains(parts[1], "c") {
			return parts[2]
		}
		return strings.Join(parts, " ")
	}
	return ""
}

var patchFile = regexp.MustCompile(`(?m)^\*\*\* (?:Add|Update|Delete) File: (.+)$`)

// patchPaths lists the files an apply_patch envelope touches.
func patchPaths(patch string) []string {
	var out []string
	for _, m := range patchFile.FindAllStringSubmatch(patch, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

// pathArgs collects string arguments whose key names a file or a path, for
// harnesses whose tool arguments are not documented field by field.
func pathArgs(args map[string]any) []string {
	var out []string
	for k, v := range args {
		lk := strings.ToLower(k)
		if s, ok := v.(string); ok && s != "" && (strings.Contains(lk, "path") || strings.Contains(lk, "file")) {
			out = append(out, s)
		}
	}
	return out
}

// --- Claude Code and Codex ---

type claude struct{ rewritesOutput bool }

type claudeInput struct {
	Event        string         `json:"hook_event_name"`
	CWD          string         `json:"cwd"`
	ToolName     string         `json:"tool_name"`
	ToolInput    map[string]any `json:"tool_input"`
	ToolResponse any            `json:"tool_response"`
	Prompt       string         `json:"prompt"`
	UserPrompt   string         `json:"user_prompt"`
}

func (c claude) Parse(event string, payload []byte, _ func(string) string) (Event, error) {
	var in claudeInput
	if err := json.Unmarshal(payload, &in); err != nil {
		return Event{}, err
	}
	if in.Event != "" {
		event = in.Event
	}
	ev := Event{Name: event, Kind: Other, Tool: in.ToolName, CWD: in.CWD}
	switch event {
	case "PreToolUse":
		switch in.ToolName {
		case "Bash", "shell", "local_shell", "exec_command", "unified_exec":
			ev.Kind, ev.Command = Shell, shellCommand(in.ToolInput["command"])
		case "Read", "NotebookRead":
			ev.Kind, ev.Paths = Read, []string{str(in.ToolInput, "file_path", "notebook_path")}
		case "Grep":
			if p := str(in.ToolInput, "path"); p != "" {
				ev.Kind, ev.Paths = Read, []string{p}
			}
		case "Write", "Edit", "MultiEdit", "NotebookEdit":
			ev.Kind, ev.Paths = Write, []string{str(in.ToolInput, "file_path", "notebook_path")}
		case "apply_patch":
			ev.Kind, ev.Paths = Write, patchPaths(shellCommand(in.ToolInput["command"])+str(in.ToolInput, "input", "patch"))
		}
	case "PostToolUse":
		if c.rewritesOutput {
			ev.Kind, ev.Response = Result, in.ToolResponse
		}
	case "UserPromptSubmit":
		ev.Kind, ev.Text = Prompt, in.Prompt
		if ev.Text == "" {
			ev.Text = in.UserPrompt
		}
	case "SessionStart":
		ev.Kind = Start
	}
	return ev, nil
}

func (c claude) Render(ev Event, v Verdict) Reply {
	specific := func(fields map[string]any) Reply {
		fields["hookEventName"] = ev.Name
		return jsonReply(map[string]any{"hookSpecificOutput": fields})
	}
	switch {
	case v.Deny && ev.Kind == Prompt:
		return jsonReply(map[string]any{"decision": "block", "reason": v.Reason})
	case v.Deny:
		return specific(map[string]any{"permissionDecision": "deny", "permissionDecisionReason": v.Reason})
	case ev.Kind == Start && v.Context != "":
		return specific(map[string]any{"additionalContext": v.Context})
	case ev.Kind == Result && v.Changed:
		return specific(map[string]any{"updatedToolOutput": v.Response})
	}
	return Reply{}
}

// --- Gemini CLI ---

type gemini struct{}

func (gemini) Parse(event string, payload []byte, _ func(string) string) (Event, error) {
	var in claudeInput // same field names: hook_event_name, tool_name, tool_input, tool_response, prompt
	if err := json.Unmarshal(payload, &in); err != nil {
		return Event{}, err
	}
	if in.Event != "" {
		event = in.Event
	}
	ev := Event{Name: event, Kind: Other, Tool: in.ToolName, CWD: in.CWD}
	switch event {
	case "BeforeTool":
		switch in.ToolName {
		case "run_shell_command":
			ev.Kind, ev.Command = Shell, str(in.ToolInput, "command")
		case "read_file", "read_many_files":
			ev.Kind, ev.Paths = Read, pathArgs(in.ToolInput)
			if ps, ok := in.ToolInput["paths"].([]any); ok {
				for _, p := range ps {
					if s, ok := p.(string); ok {
						ev.Paths = append(ev.Paths, s)
					}
				}
			}
		case "write_file", "replace":
			ev.Kind, ev.Paths = Write, pathArgs(in.ToolInput)
		}
	case "AfterTool":
		ev.Kind, ev.Response = Result, in.ToolResponse
	case "BeforeAgent":
		ev.Kind, ev.Text = Prompt, in.Prompt
	case "SessionStart":
		ev.Kind = Start
	}
	return ev, nil
}

func (gemini) Render(ev Event, v Verdict) Reply {
	switch {
	case v.Deny:
		return jsonReply(map[string]any{"decision": "deny", "reason": v.Reason})
	case ev.Kind == Start && v.Context != "":
		return jsonReply(map[string]any{"hookSpecificOutput": map[string]any{"additionalContext": v.Context}})
	case ev.Kind == Result && v.Changed:
		// Exit 2 on AfterTool replaces the tool result with stderr.
		text := ""
		if m, ok := v.Response.(map[string]any); ok {
			text = str(m, "llmContent", "output", "returnDisplay")
		}
		if text == "" {
			b, _ := json.Marshal(v.Response)
			text = string(b)
		}
		return Reply{Stderr: []byte(text), Exit: 2}
	}
	return Reply{}
}

// --- Cursor ---

type cursor struct{}

type cursorInput struct {
	Event    string `json:"hook_event_name"`
	Command  string `json:"command"`
	CWD      string `json:"cwd"`
	FilePath string `json:"file_path"`
	Prompt   string `json:"prompt"`
}

func (cursor) Parse(event string, payload []byte, _ func(string) string) (Event, error) {
	var in cursorInput // beforeReadFile also sends the file's content; it is never kept
	if err := json.Unmarshal(payload, &in); err != nil {
		return Event{}, err
	}
	if in.Event != "" {
		event = in.Event
	}
	ev := Event{Name: event, Kind: Other, CWD: in.CWD}
	switch event {
	case "beforeShellExecution":
		ev.Kind, ev.Command, ev.Tool = Shell, in.Command, "shell"
	case "beforeReadFile":
		ev.Kind, ev.Paths, ev.Tool = Read, []string{in.FilePath}, "read"
	case "beforeSubmitPrompt":
		ev.Kind, ev.Text = Prompt, in.Prompt
	case "sessionStart":
		ev.Kind = Start
	}
	return ev, nil
}

func (cursor) Render(ev Event, v Verdict) Reply {
	switch {
	case v.Deny && ev.Kind == Prompt:
		return jsonReply(map[string]any{"continue": false, "user_message": v.Reason})
	case v.Deny:
		return jsonReply(map[string]any{"permission": "deny", "user_message": v.Reason, "agent_message": v.Reason})
	case ev.Kind == Start && v.Context != "":
		return jsonReply(map[string]any{"additional_context": v.Context})
	}
	return Reply{}
}

// --- OpenCode: its plugin (plugins/opencode/passess.js) speaks this ---

type opencode struct{}

type opencodeInput struct {
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
	Output *string        `json:"output"`
	Text   *string        `json:"text"`
	CWD    string         `json:"cwd"`
}

func (opencode) Parse(event string, payload []byte, _ func(string) string) (Event, error) {
	var in opencodeInput
	if err := json.Unmarshal(payload, &in); err != nil {
		return Event{}, err
	}
	ev := Event{Name: event, Kind: Other, Tool: in.Tool, CWD: in.CWD}
	switch event {
	case "tool.execute.before":
		switch in.Tool {
		case "bash":
			ev.Kind, ev.Command = Shell, str(in.Args, "command")
		case "read", "grep", "list":
			if p := str(in.Args, "filePath", "path"); p != "" {
				ev.Kind, ev.Paths = Read, []string{p}
			}
		case "write", "edit", "patch":
			if p := str(in.Args, "filePath", "path"); p != "" {
				ev.Kind, ev.Paths = Write, []string{p}
			}
		}
	case "tool.execute.after":
		if in.Output != nil {
			ev.Kind, ev.Text = Result, *in.Output
		}
	case "chat.message":
		if in.Text != nil {
			ev.Kind, ev.Text = Prompt, *in.Text
		}
	}
	return ev, nil
}

func (opencode) Render(ev Event, v Verdict) Reply {
	switch {
	case v.Deny:
		return jsonReply(map[string]any{"block": v.Reason})
	case ev.Kind == Result && v.Changed:
		return jsonReply(map[string]any{"output": v.Output})
	}
	return Reply{}
}

// --- Kiro: hooks in an agent profile; exit 2 blocks, stderr is the reason ---

type kiro struct{}

func (kiro) Parse(event string, payload []byte, getenv func(string) string) (Event, error) {
	var in claudeInput
	if len(strings.TrimSpace(string(payload))) > 0 {
		if err := json.Unmarshal(payload, &in); err != nil {
			return Event{}, err
		}
	}
	if in.Event != "" {
		event = in.Event
	}
	ev := Event{Name: event, Kind: Other, Tool: in.ToolName, CWD: in.CWD}
	switch event {
	case "preToolUse":
		switch in.ToolName {
		case "execute_bash", "shell":
			ev.Kind, ev.Command = Shell, str(in.ToolInput, "command")
		case "fs_read", "read":
			ev.Kind, ev.Paths = Read, pathArgs(in.ToolInput)
			if ops, ok := in.ToolInput["operations"].([]any); ok {
				for _, op := range ops {
					if m, ok := op.(map[string]any); ok {
						ev.Paths = append(ev.Paths, pathArgs(m)...)
					}
				}
			}
		case "fs_write", "write":
			ev.Kind, ev.Paths = Write, pathArgs(in.ToolInput)
		}
	case "userPromptSubmit":
		ev.Kind, ev.Text = Prompt, in.Prompt
		if ev.Text == "" && getenv != nil {
			ev.Text = getenv("USER_PROMPT")
		}
	case "agentSpawn":
		ev.Kind = Start
	}
	return ev, nil
}

func (kiro) Render(ev Event, v Verdict) Reply {
	switch {
	case v.Deny:
		return Reply{Stderr: []byte(v.Reason + "\n"), Exit: 2}
	case ev.Kind == Start && v.Context != "":
		return Reply{Stdout: []byte(v.Context + "\n")} // stdout of agentSpawn joins the context
	}
	return Reply{}
}

// --- Antigravity: tool events only ---

type antigravity struct{}

type antigravityInput struct {
	ToolCall struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	} `json:"toolCall"`
	WorkspacePaths []string `json:"workspacePaths"`
}

func (antigravity) Parse(event string, payload []byte, _ func(string) string) (Event, error) {
	var in antigravityInput
	if err := json.Unmarshal(payload, &in); err != nil {
		return Event{}, err
	}
	ev := Event{Name: event, Kind: Other, Tool: in.ToolCall.Name}
	if len(in.WorkspacePaths) > 0 {
		ev.CWD = in.WorkspacePaths[0]
	}
	if event != "PreToolUse" {
		return ev, nil
	}
	switch in.ToolCall.Name {
	case "run_command":
		ev.Kind, ev.Command = Shell, str(in.ToolCall.Args, "CommandLine")
		if c := str(in.ToolCall.Args, "Cwd"); c != "" {
			ev.CWD = c
		}
	case "view_file", "view_file_outline", "view_code_item", "grep_search":
		ev.Kind, ev.Paths = Read, pathArgs(in.ToolCall.Args)
	case "write_to_file", "replace_file_content", "multi_replace_file_content":
		ev.Kind, ev.Paths = Write, pathArgs(in.ToolCall.Args)
	}
	return ev, nil
}

func (antigravity) Render(_ Event, v Verdict) Reply {
	if v.Deny {
		return jsonReply(map[string]any{"decision": "deny", "reason": v.Reason})
	}
	return Reply{}
}
