package harness

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/afsharid/passess/internal/jsonedit"
)

// JSONSpec describes a harness whose MCP servers live in a JSON or JSONC file.
type JSONSpec struct {
	ID, Label string
	// Paths are where the config may be, first match wins: relative to HOME,
	// or to XDG_CONFIG_HOME (default ~/.config) when they start with "$XDG/".
	Paths []string
	// Create lets passess write a missing config at Paths[0], in a directory
	// that already exists, and only where the harness documents that path.
	// With Bins set, one of them must also be on PATH.
	Create bool
	Bins   []string
	// Servers is the JSON path of the object that maps names to servers.
	Servers []string
	// Entry is what passess writes for a server that runs argv.
	Entry func(argv []string) any
	// Instructions is the user-level instructions file, same path rules; ""
	// when the harness reads none.
	Instructions string
	// AddArgv and RemoveArgv, when set, make writes go through the harness's
	// own CLI (which then must be on PATH); the file is only read.
	AddArgv    func(name string, argv []string) []string
	RemoveArgv func(name string) []string
}

// JSONFile adapts a JSONSpec.
type JSONFile struct {
	Spec       JSONSpec
	Home       string
	ConfigHome string // XDG_CONFIG_HOME; "" means HOME/.config
}

func (j JSONFile) ID() string    { return j.Spec.ID }
func (j JSONFile) Label() string { return j.Spec.Label }

func (j JSONFile) abs(p string) string {
	if rest, ok := strings.CutPrefix(p, "$XDG/"); ok {
		base := j.ConfigHome
		if base == "" {
			base = filepath.Join(j.Home, ".config")
		}
		return filepath.Join(base, rest)
	}
	return filepath.Join(j.Home, p)
}

// existing lists the candidate configs that exist, as the files they are:
// editing a symlinked config must change its target, not replace the link.
func (j JSONFile) existing() []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range j.Spec.Paths {
		real, err := filepath.EvalSymlinks(j.abs(p))
		if err != nil || seen[real] {
			continue
		}
		if st, err := os.Stat(real); err == nil && st.Mode().IsRegular() {
			seen[real] = true
			out = append(out, real)
		}
	}
	return out
}

// ConfigPath is the config file passess reads and edits.
func (j JSONFile) ConfigPath() string {
	if ex := j.existing(); len(ex) > 0 {
		return ex[0]
	}
	if len(j.Spec.Paths) == 0 {
		return ""
	}
	return j.abs(j.Spec.Paths[0])
}

func (j JSONFile) InstructionsPath() string {
	if j.Spec.Instructions == "" {
		return ""
	}
	return j.abs(j.Spec.Instructions)
}

func (j JSONFile) hasBin() bool {
	for _, b := range j.Spec.Bins {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	return false
}

// Installed: the config exists; or the harness CLI that writes it is on PATH;
// or passess may create it and the directory it goes in exists. passess never
// creates a harness's directory.
func (j JSONFile) Installed() bool {
	if len(j.Spec.Paths) == 0 {
		return false
	}
	if len(j.existing()) > 0 {
		return true
	}
	if j.Spec.AddArgv != nil {
		return j.hasBin()
	}
	if !j.Spec.Create || (len(j.Spec.Bins) > 0 && !j.hasBin()) {
		return false
	}
	st, err := os.Stat(filepath.Dir(j.abs(j.Spec.Paths[0])))
	return err == nil && st.IsDir()
}

// servers decodes the servers object; a missing file has none.
func (j JSONFile) servers() (map[string]map[string]any, error) {
	ex := j.existing()
	switch {
	case len(ex) == 0:
		return nil, nil
	case len(ex) > 1:
		return nil, fmt.Errorf("both %s and %s exist; passess cannot tell which one %s reads, so merge them into one", ex[0], ex[1], j.Spec.Label)
	}
	data, err := os.ReadFile(ex[0])
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var doc map[string]any
	if err := jsonedit.Decode(data, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON", ex[0])
	}
	var at any = doc
	for _, key := range j.Spec.Servers {
		m, ok := at.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: %s is not an object", ex[0], strings.Join(j.Spec.Servers, "."))
		}
		at = m[key]
	}
	if at == nil {
		return nil, nil
	}
	raw, ok := at.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: %s is not an object", ex[0], strings.Join(j.Spec.Servers, "."))
	}
	out := map[string]map[string]any{}
	for name, v := range raw {
		if s, ok := v.(map[string]any); ok {
			out[name] = s
		}
	}
	return out, nil
}

// parseServer reads the fields every harness names a little differently: a
// command string or array, env or environment, url, serverUrl or httpUrl.
func parseServer(s map[string]any) (r Raw, env, headers map[string]any) {
	switch c := s["command"].(type) {
	case string:
		r.Command = c
	case []any:
		if parts := stringsOf(c); len(parts) > 0 {
			r.Command, r.Args = parts[0], parts[1:]
		}
	}
	r.Args = append(r.Args, stringsOf(s["args"])...)
	for _, k := range []string{"url", "serverUrl", "httpUrl"} {
		if u, ok := s[k].(string); ok && u != "" {
			r.URL = u
			break
		}
	}
	env, _ = s["env"].(map[string]any)
	if env == nil {
		env, _ = s["environment"].(map[string]any)
	}
	headers, _ = s["headers"].(map[string]any)
	r.Env, r.Headers = strs(env), strs(headers)
	return r, env, headers
}

func strs(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func (j JSONFile) Entries() ([]Entry, error) {
	servers, err := j.servers()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for name, s := range servers {
		r, env, headers := parseServer(s)
		e := Entry{Name: name, Command: r.Command, Args: r.Args, URL: r.URL}
		var leaks []string
		e.EnvKeys, leaks = keysAndLeaks(env, "env.")
		e.Leaks = append(e.Leaks, leaks...)
		e.HeaderKeys, leaks = keysAndLeaks(headers, "headers.")
		e.Leaks = append(e.Leaks, leaks...)
		out = append(out, e)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (j JSONFile) Raw(name string) (Raw, bool, error) {
	servers, err := j.servers()
	if err != nil {
		return Raw{}, false, err
	}
	s, ok := servers[name]
	if !ok {
		return Raw{}, false, nil
	}
	r, _, _ := parseServer(s)
	return r, true, nil
}

func (j JSONFile) AddCommand(name string, argv []string) []string {
	if j.Spec.AddArgv == nil {
		return nil
	}
	return j.Spec.AddArgv(name, argv)
}

func (j JSONFile) RemoveCommand(name string) []string {
	if j.Spec.RemoveArgv == nil {
		return nil
	}
	return j.Spec.RemoveArgv(name)
}

// Edit applies actions to the config's bytes.
func (j JSONFile) Edit(data []byte, actions []Action) ([]byte, error) {
	if j.Spec.Entry == nil {
		return nil, errors.New(j.Spec.Label + " is changed through its own CLI")
	}
	var err error
	for _, a := range actions {
		if a.Kind == "remove" {
			data, err = jsonedit.Delete(data, j.Spec.Servers, a.Server)
		} else {
			data, err = jsonedit.Set(data, j.Spec.Servers, a.Server, j.Spec.Entry(a.Argv))
		}
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}
