package cli

import (
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/afsharid/passess/internal/apps"
	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/detect"
	"github.com/afsharid/passess/internal/harness"
)

// appReport is a desktop app that reads its own keys through passess helper
// (ADR 11): whether its plugin is in place and loaded, and whether each key
// it asks for is connected to it.
type appReport struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Config string `json:"config"` // the profile patch passess splices into
	// Plugin is ok when the plugin file and the row that loads it are both
	// as this passess writes them, missing when neither is, drift otherwise.
	Plugin string `json:"plugin"`
	// Active is when the plugin started in the running app, "" when no
	// running app has it loaded.
	Active  string   `json:"active,omitempty"`
	Keys    []appKey `json:"keys"`
	Changes []string `json:"changes"` // what install or uninstall does, or did with --apply
	Backup  string   `json:"backup,omitempty"`
	Errors  []string `json:"errors"`
}

// Key states: connected to the app by name, connected to every agent (which
// passess helper does not count for an app), connected to others only, or not
// a secret passess has.
const (
	keyConnected  = "connected"
	keyEveryAgent = "every-agent"
	keyElsewhere  = "elsewhere"
	keyUndefined  = "undefined"
)

type appKey struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// appIDs are the apps install and status know, beside the harnesses.
var appIDs = []string{"dsh"}

// splitApps separates the app IDs among names from the harness IDs.
func splitApps(names []string) (appNames, rest []string) {
	for _, n := range names {
		if slices.Contains(appIDs, n) {
			appNames = append(appNames, n)
		} else {
			rest = append(rest, n)
		}
	}
	return appNames, rest
}

func dataDir(getenv func(string) string) string {
	if x := getenv("XDG_DATA_HOME"); x != "" {
		return filepath.Join(x, "passess")
	}
	return filepath.Join(getenv("HOME"), ".local", "share", "passess")
}

func dshOf(st *Streams) apps.DSH {
	return apps.NewDSH(st.Getenv, dataDir(st.Getenv), stateDir(st.Getenv))
}

// appReports reports, and with apply changes, the named apps, or every
// installed one when all is set. ok is false when one has errors or, for
// status, is not set up.
func appReports(st *Streams, verb string, names []string, all bool, u *config.User, apply bool) (out []appReport, ok bool) {
	ok = true
	d := dshOf(st)
	if (!all || !d.Installed()) && !slices.Contains(names, "dsh") {
		return []appReport{}, ok
	}
	r := dshReport(d, verb, u)
	if apply && len(r.Changes) > 0 {
		backup, err := harness.Backup(filepath.Join(stateDir(st.Getenv), "backups"), []string{d.Patch}, time.Now())
		if err != nil {
			r.Errors = append(r.Errors, "backup failed, nothing changed: "+err.Error())
		} else {
			change := d.Install
			if verb == "uninstall" {
				change = d.Uninstall
			}
			if err := change(); err != nil {
				r.Errors = append(r.Errors, err.Error())
			} else {
				changes := r.Changes
				r = dshReport(d, verb, u)
				r.Changes, r.Backup = changes, backup
			}
		}
	}
	if len(r.Errors) > 0 || (verb == "status" && r.Plugin != apps.StateOK) {
		ok = false
	}
	return []appReport{r}, ok
}

func dshReport(d apps.DSH, verb string, u *config.User) appReport {
	r := appReport{ID: "dsh", Label: detect.Label("dsh"), Config: d.Patch, Keys: []appKey{}, Changes: []string{}, Errors: []string{}}
	file, row := d.PluginState(), d.RowState()
	switch {
	case file == apps.StateOK && row == apps.StateOK:
		r.Plugin = apps.StateOK
	case file == apps.StateMissing && row == apps.StateMissing:
		r.Plugin = apps.StateMissing
	default:
		r.Plugin = apps.StateDrift
	}
	r.Active = d.Active()
	switch verb {
	case "install":
		if file != apps.StateOK {
			r.Changes = append(r.Changes, "write the plugin to "+d.Plugin)
		}
		if row != apps.StateOK {
			r.Changes = append(r.Changes, "load it from "+d.Patch)
		}
	case "uninstall":
		if row != apps.StateMissing {
			r.Changes = append(r.Changes, "remove passess's rows from "+d.Patch)
		}
		if file != apps.StateMissing {
			r.Changes = append(r.Changes, "remove "+d.Plugin)
		}
	}
	for _, name := range d.Keys() {
		k := appKey{Name: name, State: keyUndefined}
		if u != nil {
			if s, ok := u.Secrets[name]; ok {
				switch {
				case s.Clients == nil:
					k.State = keyEveryAgent
				case slices.Contains(s.Clients, "dsh"):
					k.State = keyConnected
				default:
					k.State = keyElsewhere
				}
			}
		}
		r.Keys = append(r.Keys, k)
	}
	return r
}

func printApps(st *Streams, verb string, applied bool, reports []appReport) (pending bool) {
	for _, r := range reports {
		fmt.Fprintf(st.Stdout, "%s  (%s)\n", r.Label, r.Config)
		active := "not loaded in a running app"
		if r.Active != "" {
			active = "loaded since " + r.Active
		}
		fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", "plugin", r.Plugin, active)
		for _, k := range r.Keys {
			fmt.Fprintf(st.Stdout, "  %-14s %-10s %s\n", k.Name, k.State, keyNote(k.State, r.Label))
		}
		for _, c := range r.Changes {
			if applied {
				fmt.Fprintf(st.Stdout, "  done: %s\n", c)
			} else {
				pending = true
				fmt.Fprintf(st.Stdout, "  would %s\n", c)
			}
		}
		if applied && r.Plugin != apps.StateMissing && verb == "install" && r.Active == "" {
			fmt.Fprintf(st.Stdout, "  note: restart %s to load it\n", r.Label)
		}
		if r.Backup != "" {
			fmt.Fprintf(st.Stdout, "  backup: %s\n", r.Backup)
		}
		for _, e := range r.Errors {
			fmt.Fprintf(st.Stdout, "  error: %s\n", e)
		}
	}
	return pending
}

func keyNote(state, label string) string {
	switch state {
	case keyConnected:
		return "reaches " + label
	case keyEveryAgent:
		return "connected to every agent; connect it to " + label + " by name"
	case keyElsewhere:
		return "connected to other agents only"
	}
	return "not a secret passess has"
}
