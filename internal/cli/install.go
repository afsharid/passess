package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	return []harness.Adapter{
		harness.Claude{Home: home},
		harness.Codex{Home: home, CodexHome: st.Getenv("CODEX_HOME")},
	}
}

// selectAdapters returns the installed harnesses, or the named ones.
func selectAdapters(st *Streams, names []string) ([]harness.Adapter, error) {
	var out []harness.Adapter
	for _, a := range adapters(st) {
		switch {
		case len(names) == 0 && a.Installed():
			out = append(out, a)
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
			return nil, fmt.Errorf("unknown harness %q (known: claude, codex)", n)
		}
	}
	return out, nil
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
	apply, force := new(bool), new(bool)
	if verb != "status" {
		apply = fs.Bool("apply", false, "make the changes (without it, only show them)")
	}
	if verb == "install" {
		force = fs.Bool("force", false, "replace entries of the same name that do not run passess")
	}
	fs.Usage = func() {
		fmt.Fprintf(st.Stderr, "Usage: passess %s [flags] [claude] [codex]\n", verb)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	augmentPath(st.Getenv)
	targets, err := selectAdapters(st, fs.Args())
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
		r := report(a, verb, desired, *force)
		if *apply && (len(r.Actions) > 0 || instructionsChange(verb, r.InstructionsState)) {
			applyReport(st, a, verb, &r)
			if len(r.Errors) == 0 {
				fresh := report(a, verb, desired, *force)
				fresh.Backup, fresh.Actions = r.Backup, r.Actions
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
	doc, _ := os.ReadFile(a.InstructionsPath())
	r.InstructionsState = harness.BlockState(string(doc))
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
	return r.InstructionsState == harness.BlockOK
}

func applyReport(st *Streams, a harness.Adapter, verb string, r *harnessReport) {
	backup, err := harness.Backup(filepath.Join(stateDir(st.Getenv), "backups"), []string{a.ConfigPath(), a.InstructionsPath()}, time.Now())
	if err != nil {
		r.Errors = append(r.Errors, "backup failed, nothing changed: "+err.Error())
		return
	}
	r.Backup = backup
	for _, action := range r.Actions {
		for _, cmd := range action.Commands {
			res, err := (provider.ExecRunner{}).Run(context.Background(), provider.Cmd{Name: cmd[0], Args: cmd[1:], Env: os.Environ()})
			if err == nil && res.Exit != 0 {
				err = errors.New(provider.CLIMessage(res.Stderr))
			}
			if err != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("%s: %v", strings.Join(cmd[:3], " "), err))
				return
			}
		}
	}
	if instructionsChange(verb, r.InstructionsState) {
		if err := writeInstructions(a.InstructionsPath(), verb); err != nil {
			r.Errors = append(r.Errors, err.Error())
		}
	}
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
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, []byte(next), perm)
}

func printHarnesses(st *Streams, verb string, out harnessOutput) {
	if len(out.Harnesses) == 0 {
		fmt.Fprintln(st.Stdout, "No supported harness found (Claude Code, Codex).")
		return
	}
	pending := false
	for _, r := range out.Harnesses {
		fmt.Fprintf(st.Stdout, "%s  (%s)\n", r.Label, r.Config)
		for _, s := range r.Servers {
			fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", s.Name, s.State, s.Detail)
		}
		fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", "instructions", r.InstructionsState, r.Instructions)
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
			fmt.Fprintf(st.Stdout, "  %s %s: %s\n", verbWord, a.Server, strings.Join(a.Commands[len(a.Commands)-1], " "))
		}
		if !out.Applied && instructionsChange(verb, r.InstructionsState) {
			pending = true
			fmt.Fprintf(st.Stdout, "  would update %s\n", r.Instructions)
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
