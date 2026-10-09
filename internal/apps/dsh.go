// Package apps sets up desktop apps that read their own API keys from passess
// (ADR 11): the plugin each one loads and the profile row that loads it.
//
// DeepSeek Harness is the first. Its plugin ships inside the passess binary,
// is written to passess's data directory and is loaded by a row passess
// splices into the user's own DSH patch file between marker comments.
package apps

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed dsh/index.mjs
var dshPlugin []byte

// Plugin and profile row states.
const (
	StateOK      = "ok"      // in place, as this passess writes it
	StateMissing = "missing" // not there
	StateDrift   = "drift"   // there, but another version or another path
)

// Markers around the rows passess owns in the DSH patch file.
const (
	BlockStart = "# passess start: written by `passess install dsh`; edits inside are replaced"
	BlockEnd   = "# passess end"
)

// DSH is DeepSeek Harness's desktop profile, as seen from one user's home.
type DSH struct {
	App     string // the app bundle
	Patch   string // the profile's cordis.patch.yml
	Plugin  string // where passess writes the plugin
	Status  string // the file the running plugin keeps
	Profile string // the profile directory
}

// NewDSH locates DSH for a home and passess's data and state directories.
// DSH_HOME moves DSH's own home, as it does for DSH.
func NewDSH(getenv func(string) string, dataDir, stateDir string) DSH {
	home := getenv("DSH_HOME")
	if home == "" {
		home = filepath.Join(getenv("HOME"), ".dsh")
	}
	profile := filepath.Join(home, "profiles", "desktop")
	return DSH{
		App:     "/Applications/DeepSeek Harness.app",
		Profile: profile,
		Patch:   filepath.Join(profile, "cordis.patch.yml"),
		Plugin:  filepath.Join(dataDir, "dsh", "index.mjs"),
		Status:  filepath.Join(stateDir, "dsh-plugin.json"),
	}
}

// Installed reports whether DSH is on this machine: its app or its profile.
func (d DSH) Installed() bool {
	for _, p := range []string{d.App, d.Profile} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// block is the patch rows that load the plugin from path. The path is a
// double-quoted scalar, which YAML reads as JSON reads a string, so no byte
// of it can end the row or start another; checkPath has already refused
// anything but a plain absolute path.
func block(path string) string {
	quoted, _ := json.Marshal(path) // a string always marshals
	return BlockStart + "\n- insert:\n    - id: passess-credentials\n      name: " + string(quoted) + "\n" + BlockEnd + "\n"
}

// checkPath refuses a plugin path that is not absolute or holds a control
// character: it comes from XDG_DATA_HOME or HOME, which whoever runs
// passess sets, and ends up in a file DSH loads code from.
func checkPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("the plugin path %q is not absolute; check XDG_DATA_HOME and HOME", path)
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return fmt.Errorf("the plugin path %q holds a control character; check XDG_DATA_HOME and HOME", path)
		}
	}
	return nil
}

// span locates passess's block in doc; ok is false without both markers.
func span(doc string) (start, end int, ok bool) {
	start = strings.Index(doc, BlockStart)
	if start < 0 {
		return 0, 0, false
	}
	rel := strings.Index(doc[start:], BlockEnd)
	if rel < 0 {
		return 0, 0, false
	}
	end = start + rel + len(BlockEnd)
	if end < len(doc) && doc[end] == '\n' {
		end++
	}
	return start, end, true
}

// PluginState compares the plugin file with the one this passess carries.
func (d DSH) PluginState() string {
	data, err := os.ReadFile(d.Plugin)
	switch {
	case err != nil:
		return StateMissing
	case !bytes.Equal(data, dshPlugin):
		return StateDrift
	}
	return StateOK
}

// RowState says whether the patch loads the plugin from where passess writes it.
func (d DSH) RowState() string {
	data, err := os.ReadFile(d.Patch)
	if err != nil {
		return StateMissing
	}
	doc := string(data)
	start, end, ok := span(doc)
	switch {
	case !ok:
		return StateMissing
	case doc[start:end] != block(d.Plugin):
		return StateDrift
	}
	return StateOK
}

// Install writes the plugin and splices the row that loads it into the
// patch, creating the patch if DSH has not yet. It changes nothing that is
// already in place.
func (d DSH) Install() error {
	if err := checkPath(d.Plugin); err != nil {
		return err
	}
	if d.PluginState() != StateOK {
		if err := os.MkdirAll(filepath.Dir(d.Plugin), 0o750); err != nil {
			return err
		}
		if err := writeAtomic(d.Plugin, dshPlugin, 0o644); err != nil {
			return err
		}
	}
	if d.RowState() == StateOK {
		return nil
	}
	data, err := os.ReadFile(d.Patch)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	doc := string(data)
	if start, end, ok := span(doc); ok {
		doc = doc[:start] + block(d.Plugin) + doc[end:]
	} else {
		if doc != "" && !strings.HasSuffix(doc, "\n") {
			doc += "\n"
		}
		doc += block(d.Plugin)
	}
	if err := os.MkdirAll(filepath.Dir(d.Patch), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(d.Patch, []byte(doc), 0o600); err != nil {
		return err
	}
	// Read it back: the file must hold this block and nothing else of ours,
	// or the user's own file goes back as it was.
	if d.RowState() != StateOK || strings.Count(doc, BlockStart) != 1 {
		if len(data) > 0 {
			_ = writeAtomic(d.Patch, data, 0o600)
		}
		return fmt.Errorf("%s did not read back as written; left as it was", d.Patch)
	}
	return nil
}

// Uninstall takes passess's block out of the patch and removes the plugin.
// A patch left with no entry gets the empty list DSH needs to start.
func (d DSH) Uninstall() error {
	data, err := os.ReadFile(d.Patch)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if start, end, ok := span(string(data)); ok {
		doc := string(data[:start]) + string(data[end:])
		if !hasEntry(doc) {
			doc += "[]\n"
		}
		if err := writeAtomic(d.Patch, []byte(doc), 0o600); err != nil {
			return err
		}
	}
	if err := os.Remove(d.Plugin); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// hasEntry reports whether a patch holds anything but comments and blanks:
// DSH refuses to start on an empty one.
func hasEntry(doc string) bool {
	for _, line := range strings.Split(doc, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}

var keyLine = regexp.MustCompile(`^\s*apiKeyEnv:\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*(#.*)?$`)

// Keys are the variables DSH's providers name for their keys (apiKeyEnv), in
// the order the patch has them. A line scan: what a status report needs, not
// a YAML reading.
func (d DSH) Keys() []string {
	data, err := os.ReadFile(d.Patch)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if m := keyLine.FindStringSubmatch(line); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// beatFresh is how long a status file counts after the plugin last wrote it:
// it writes every 30 seconds while loaded.
const beatFresh = 90 * time.Second

// Active returns when the plugin started in a running DSH, or "" when none
// has it loaded: the plugin rewrites its status file as a heartbeat, so a
// stale one is a DSH that ended, or a process of it that loaded the plugin
// and exited, without unloading it.
func (d DSH) Active() string {
	info, err := os.Stat(d.Status)
	if err != nil || time.Since(info.ModTime()) > beatFresh {
		return ""
	}
	data, err := os.ReadFile(d.Status)
	if err != nil {
		return ""
	}
	var s struct {
		Since string `json:"since"`
	}
	if json.Unmarshal(data, &s) != nil || s.Since == "" {
		return ""
	}
	return s.Since
}

// writeAtomic replaces path with data via a temporary file beside it.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
