package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/harness"
	"github.com/afsharid/passess/internal/provider"
)

func init() {
	commands["status"] = command{"show how each harness starts passess's MCP servers", runStatus}
	commands["install"] = command{"make harnesses start MCP servers through passess (dry run unless --apply)", runInstall}
	commands["uninstall"] = command{"remove passess's MCP entries and instructions from harnesses (dry run unless --apply)", runUninstall}
}

type harnessReport struct {
	ID                string                 `json:"id"`
	Label             string                 `json:"label"`
	Config            string                 `json:"config"`
	Servers           []harness.ServerStatus `json:"servers"`
	Unmanaged         []harness.Entry        `json:"unmanaged"`
	Instructions      string                 `json:"instructions"`
	InstructionsState string                 `json:"instructions_state"`
	Hooks             string                 `json:"hooks"` // ok | missing | drift | unavailable | none
	HooksPath         string                 `json:"hooks_path,omitempty"`
	HooksNote         string                 `json:"hooks_note,omitempty"`
	Actions           []harness.Action       `json:"actions"`
	Backup            string                 `json:"backup,omitempty"`
	Errors            []string               `json:"errors"`
}

type harnessOutput struct {
	Applied   bool            `json:"applied"`
	Harnesses []harnessReport `json:"harnesses"`
}

func adapters(st *Streams) []harness.Adapter {
	home := st.Getenv("HOME")
	out := []harness.Adapter{
		harness.Claude{Home: home},
		harness.Codex{Home: home, CodexHome: st.Getenv("CODEX_HOME")},
	}
	for _, spec := range harness.JSONSpecs(runtime.GOOS) {
		out = append(out, harness.JSONFile{Spec: spec, Home: home, ConfigHome: st.Getenv("XDG_CONFIG_HOME")})
	}
	return out
}

// selectAdapters returns the installed harnesses, or the named ones.
func selectAdapters(st *Streams, names []string) ([]harness.Adapter, error) {
	var out []harness.Adapter
	for _, a := range adapters(st) {
		switch {
		case len(names) == 0 && a.Installed():
			out = append(out, a)
		case contains(names, a.ID()) && a.ConfigPath() == "":
			return nil, fmt.Errorf("%s has no config location passess knows on this system", a.Label())
		case contains(names, a.ID()):
			out = append(out, a)
		}
	}
	for _, n := range names {
		found := false
		for _, a := range adapters(st) {
			found = found || a.ID() == n
		}
		if !found {
			return nil, fmt.Errorf("unknown harness %q (known: %s)", n, knownHarnesses(st))
		}
	}
	return out, nil
}

func knownHarnesses(st *Streams) string {
	var ids []string
	for _, a := range adapters(st) {
		ids = append(ids, a.ID())
	}
	return strings.Join(ids, ", ")
}

// passessPath is the binary harnesses should start: the PATH entry if it is
// this binary (it survives Homebrew upgrades), otherwise this binary itself.
func passessPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "passess"
	}
	if lp, err := exec.LookPath("passess"); err == nil {
		a, errA := os.Stat(lp)
		b, errB := os.Stat(exe)
		if errA == nil && errB == nil && os.SameFile(a, b) {
			if abs, err := filepath.Abs(lp); err == nil {
				return abs
			}
		}
	}
	return exe
}

func desiredServers(u *config.User) []harness.Desired {
	names := make([]string, 0, len(u.MCP))
	for n := range u.MCP {
		names = append(names, n)
	}
	sort.Strings(names)
	bin := passessPath()
	out := make([]harness.Desired, 0, len(names))
	for _, n := range names {
		out = append(out, harness.Desired{Name: n, Argv: []string{bin, "mcp-exec", n}})
	}
	return out
}

func stateDir(getenv func(string) string) string {
	if x := getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "passess")
	}
	return filepath.Join(getenv("HOME"), ".local", "state", "passess")
}

func runStatus(st *Streams, args []string) int {
	return harnessCommand(st, "status", args)
}

func runInstall(st *Streams, args []string) int {
	return harnessCommand(st, "install", args)
}

func runUninstall(st *Streams, args []string) int {
	return harnessCommand(st, "uninstall", args)
}

func harnessCommand(st *Streams, verb string, args []string) int {
	fs := flag.NewFlagSet(verb, flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	apply, force, noHooks := new(bool), new(bool), new(bool)
	if verb != "status" {
		apply = fs.Bool("apply", false, "make the changes (without it, only show them)")
	}
	if verb == "install" {
		force = fs.Bool("force", false, "replace entries of the same name that do not run passess")
		noHooks = fs.Bool("no-hooks", false, "do not register passess's hook handler")
	}
	fs.Usage = func() {
		fmt.Fprintf(st.Stderr, "Usage: passess %s [flags] [HARNESS...]   (%s)\n", verb, knownHarnesses(st))
		fs.PrintDefaults()
	}
	names, err := parseAnywhere(fs, args)
	if err != nil {
		return ExitUsage
	}
	augmentPath(st.Getenv)
	targets, err := selectAdapters(st, names)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}

	var desired []harness.Desired
	if verb != "uninstall" {
		path, err := config.UserPath(st.Getenv)
		if err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		u, err := config.LoadUser(path)
		if err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		desired = desiredServers(u)
	}

	out := harnessOutput{Applied: *apply, Harnesses: []harnessReport{}}
	healthy := true
	for _, a := range targets {
		h := hooksFor(st, a.ID())
		r := report(a, verb, desired, *force)
		fillHooks(&r, h)
		hooks := hooksChange(verb, r.Hooks, *noHooks)
		if *apply && (len(r.Actions) > 0 || instructionsChange(verb, r.InstructionsState) || hooks) {
			applyReport(st, a, verb, &r, h, hooks)
			if len(r.Errors) == 0 {
				fresh := report(a, verb, desired, *force)
				fillHooks(&fresh, h)
				fresh.Backup, fresh.Actions = r.Backup, r.Actions
				if hooks && verb == "install" && h != nil {
					fresh.HooksNote = h.Spec.Note
				}
				r = fresh
			}
		}
		if len(r.Errors) > 0 || (verb == "status" && !settled(r)) {
			healthy = false
		}
		out.Harnesses = append(out.Harnesses, r)
	}

	if *asJSON {
		if code := writeJSON(st, out); code != ExitOK {
			return code
		}
	} else {
		printHarnesses(st, verb, out)
	}
	if !healthy {
		return 1
	}
	return ExitOK
}

func report(a harness.Adapter, verb string, desired []harness.Desired, force bool) harnessReport {
	r := harnessReport{ID: a.ID(), Label: a.Label(), Config: a.ConfigPath(), Instructions: a.InstructionsPath(),
		Servers: []harness.ServerStatus{}, Unmanaged: []harness.Entry{}, Actions: []harness.Action{}, Errors: []string{}}
	entries, err := a.Entries()
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		return r
	}
	self := passessPath()
	wanted := map[string]bool{}
	for _, d := range desired {
		wanted[d.Name] = true
	}
	for _, e := range entries {
		if !e.ManagedBy(self) && !wanted[e.Name] {
			r.Unmanaged = append(r.Unmanaged, e)
		}
	}
	r.InstructionsState = harness.BlockNone
	if p := a.InstructionsPath(); p != "" {
		doc, _ := os.ReadFile(p)
		r.InstructionsState = harness.BlockState(string(doc))
	}
	if verb == "uninstall" {
		r.Actions = append(r.Actions, harness.PlanRemoval(a, entries, self)...)
		return r
	}
	statuses, actions := harness.Plan(a, desired, entries, force)
	r.Servers = append(r.Servers, statuses...)
	if verb == "install" {
		r.Actions = append(r.Actions, actions...)
	}
	return r
}

func instructionsChange(verb, state string) bool {
	if state == harness.BlockNone {
		return false
	}
	if verb == "uninstall" {
		return state != harness.BlockMissing
	}
	return verb == "install" && state != harness.BlockOK
}

// settled reports whether a harness needs nothing from passess.
func settled(r harnessReport) bool {
	for _, s := range r.Servers {
		if s.State != harness.StateOK {
			return false
		}
	}
	for _, e := range r.Unmanaged {
		if len(e.Leaks) > 0 {
			return false
		}
	}
	return r.InstructionsState == harness.BlockOK || r.InstructionsState == harness.BlockNone
}

// hooksFor is the hook config of a harness, or nil if passess registers none.
func hooksFor(st *Streams, id string) *harness.Hooks {
	for _, spec := range harness.HookSpecs() {
		if spec.ID == id {
			return &harness.Hooks{Spec: spec, Home: st.Getenv("HOME"), ConfigHome: st.Getenv("XDG_CONFIG_HOME")}
		}
	}
	return nil
}

func fillHooks(r *harnessReport, h *harness.Hooks) {
	if h == nil {
		r.Hooks = "none"
		return
	}
	r.HooksPath = h.File()
	state, err := h.State(passessPath())
	switch {
	case err != nil:
		r.Hooks = "unknown"
		r.Errors = append(r.Errors, err.Error())
	case state == harness.StateMissing && !h.Installable():
		r.Hooks = "unavailable"
	default:
		r.Hooks = state
	}
}

func hooksChange(verb, state string, skip bool) bool {
	switch verb {
	case "install":
		return !skip && (state == harness.StateMissing || state == harness.StateDrift)
	case "uninstall":
		return state == harness.StateOK || state == harness.StateDrift
	}
	return false
}

// editHooks registers passess's hook handler in h, or removes every passess
// handler from it, and restores the file if it does not read back so.
func editHooks(h harness.Hooks, self string, install bool) error {
	path := h.File()
	before, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	after, err := h.Edit(before, self, install)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	perm := os.FileMode(0o600)
	if h.Spec.Style == harness.HookPlugin {
		perm = 0o644 // code, no secret
	}
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	if after == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	} else {
		if h.Spec.Style == harness.HookPlugin {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				return err
			}
		}
		if err := writeFileAtomic(path, after, perm); err != nil {
			return err
		}
	}
	want := harness.StateOK
	if !install {
		want = harness.StateMissing
	}
	if got, err := h.State(self); err != nil || got != want {
		if before == nil {
			_ = os.Remove(path)
		} else {
			_ = writeFileAtomic(path, before, perm)
		}
		return fmt.Errorf("%s left unchanged: its hooks read back as %s", path, got)
	}
	return nil
}

func applyReport(st *Streams, a harness.Adapter, verb string, r *harnessReport, h *harness.Hooks, hooks bool) {
	paths := []string{a.ConfigPath(), a.InstructionsPath()}
	if h != nil {
		paths = append(paths, h.File())
	}
	backup, err := harness.Backup(filepath.Join(stateDir(st.Getenv), "backups"), paths, time.Now())
	if err != nil {
		r.Errors = append(r.Errors, "backup failed, nothing changed: "+err.Error())
		return
	}
	r.Backup = backup
	if err := applyActions(a, r.Actions); err != nil {
		r.Errors = append(r.Errors, err.Error())
		return
	}
	if instructionsChange(verb, r.InstructionsState) {
		if err := writeInstructions(a.InstructionsPath(), verb); err != nil {
			r.Errors = append(r.Errors, err.Error())
		}
	}
	if hooks && h != nil {
		if err := editHooks(*h, passessPath(), verb == "install"); err != nil {
			r.Errors = append(r.Errors, err.Error())
		}
	}
}

// applyActions carries out actions on one harness: through its CLI, or by
// editing its config when the harness has no command for it.
func applyActions(a harness.Adapter, actions []harness.Action) error {
	var edits []harness.Action
	for _, action := range actions {
		if len(action.Commands) == 0 {
			edits = append(edits, action)
			continue
		}
		for _, cmd := range action.Commands {
			res, err := (provider.ExecRunner{}).Run(context.Background(), provider.Cmd{Name: cmd[0], Args: cmd[1:], Env: os.Environ()})
			if err == nil && res.Exit != 0 {
				err = errors.New(provider.CLIMessage(res.Stderr))
			}
			if err != nil {
				return fmt.Errorf("%s: %w", strings.Join(cmd[:min(3, len(cmd))], " "), err)
			}
		}
	}
	if len(edits) == 0 {
		return nil
	}
	ed, ok := a.(harness.Editor)
	if !ok {
		return fmt.Errorf("%s: no way to %s %s", a.Label(), edits[0].Kind, edits[0].Server)
	}
	return editConfig(a, ed, edits)
}

// editConfig changes the harness config in place (a symlinked config keeps
// its link: ConfigPath is the file it points at), then reads it back through
// the adapter and restores the old bytes if the harness would not see the
// change.
func editConfig(a harness.Adapter, ed harness.Editor, actions []harness.Action) error {
	path := a.ConfigPath()
	before, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	after, err := ed.Edit(before, actions)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	perm := os.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	if err := writeFileAtomic(path, after, perm); err != nil { // never creates the harness's directory
		return err
	}
	if err := readsBack(a, actions); err != nil {
		if before == nil {
			_ = os.Remove(path)
		} else {
			_ = writeFileAtomic(path, before, perm)
		}
		return fmt.Errorf("%s left unchanged: %w", path, err)
	}
	return nil
}

func readsBack(a harness.Adapter, actions []harness.Action) error {
	entries, err := a.Entries()
	if err != nil {
		return err
	}
	byName := map[string]harness.Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	for _, act := range actions {
		e, ok := byName[act.Server]
		switch {
		case act.Kind == "remove" && ok:
			return fmt.Errorf("%s is still there after removing it", act.Server)
		case act.Kind != "remove" && (!ok || e.Command != act.Argv[0] || !slices.Equal(e.Args, act.Argv[1:])):
			return fmt.Errorf("%s does not read back as %s", act.Server, strings.Join(act.Argv, " "))
		}
	}
	return nil
}

func writeInstructions(path, verb string) error {
	doc, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	perm := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	next := harness.Splice(string(doc))
	if verb == "uninstall" {
		next = harness.Unsplice(string(doc))
		// A file passess named for itself goes once its block is out.
		if filepath.Base(path) == "passess.md" && strings.TrimSpace(next) == "" {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(next), perm)
}

// describeAction is the command passess runs, or the edit it makes.
func describeAction(a harness.Action, config string) string {
	switch {
	case len(a.Commands) > 0:
		return strings.Join(a.Commands[len(a.Commands)-1], " ")
	case a.Kind == "remove":
		return "remove it from " + config
	}
	return "set it to `" + strings.Join(a.Argv, " ") + "` in " + config
}

func printHarnesses(st *Streams, verb string, out harnessOutput) {
	if len(out.Harnesses) == 0 {
		fmt.Fprintf(st.Stdout, "No supported harness found (%s).\n", knownHarnesses(st))
		return
	}
	pending := false
	for _, r := range out.Harnesses {
		fmt.Fprintf(st.Stdout, "%s  (%s)\n", r.Label, r.Config)
		for _, s := range r.Servers {
			fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", s.Name, s.State, s.Detail)
		}
		fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", "instructions", r.InstructionsState, r.Instructions)
		if r.Hooks != "none" {
			fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", "hooks", r.Hooks, r.HooksPath)
		}
		for _, e := range r.Unmanaged {
			if len(e.Leaks) > 0 {
				fmt.Fprintf(st.Stdout, "  %-14s %-10s credentials in clear: %s\n", e.Name, "LEAK", strings.Join(e.Leaks, ", "))
			}
		}
		for _, a := range r.Actions {
			pending = true
			verbWord := "would " + a.Kind
			if out.Applied {
				verbWord = map[string]string{"add": "added", "replace": "replaced", "remove": "removed"}[a.Kind]
			}
			fmt.Fprintf(st.Stdout, "  %s %s: %s\n", verbWord, a.Server, describeAction(a, r.Config))
		}
		if !out.Applied && instructionsChange(verb, r.InstructionsState) {
			pending = true
			fmt.Fprintf(st.Stdout, "  would update %s\n", r.Instructions)
		}
		if !out.Applied && hooksChange(verb, r.Hooks, false) && verb != "status" {
			pending = true
			if verb == "install" {
				fmt.Fprintf(st.Stdout, "  would register the passess hook handler in %s\n", r.HooksPath)
			} else {
				fmt.Fprintf(st.Stdout, "  would remove passess hooks from %s\n", r.HooksPath)
			}
		}
		if r.HooksNote != "" {
			fmt.Fprintf(st.Stdout, "  note: %s\n", r.HooksNote)
		}
		if r.Backup != "" {
			fmt.Fprintf(st.Stdout, "  backup: %s\n", r.Backup)
		}
		for _, e := range r.Errors {
			fmt.Fprintf(st.Stdout, "  error: %s\n", e)
		}
	}
	if !out.Applied && pending && verb != "status" {
		fmt.Fprintf(st.Stdout, "\nDry run: nothing changed. Run `passess %s --apply` to make these changes.\n", verb)
	}
}
