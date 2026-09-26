package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

func init() {
	commands["list"] = command{"list secret names, their backends and who may receive them", runList}
}

type listedSecret struct {
	Name     string   `json:"name"`
	Backends []string `json:"backends"`
	Allow    []string `json:"allow"`
	Note     string   `json:"note,omitempty"`
	Project  bool     `json:"needed_by_project"`
}

type listOutput struct {
	Config  string         `json:"config"`
	Project string         `json:"project,omitempty"`
	Secrets []listedSecret `json:"secrets"`
	Missing []string       `json:"missing"` // needed by the project, not defined by the user
}

func runList(st *Streams, args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	u, proj, code := loadConfig(st)
	if code != 0 {
		return code
	}
	out := listOutput{Config: u.Path, Secrets: []listedSecret{}, Missing: []string{}}
	if proj != nil {
		out.Project = proj.Path
	}
	for _, name := range u.SortedNames() {
		s := u.Secrets[name]
		var backends []string
		for _, r := range s.Refs {
			if !contains(backends, r.Scheme) {
				backends = append(backends, r.Scheme)
			}
		}
		_, needed := proj.NeedsName(name)
		out.Secrets = append(out.Secrets, listedSecret{Name: name, Backends: backends, Allow: nonNil(s.Allow), Note: s.Note, Project: needed})
	}
	if proj != nil {
		for name := range proj.Needs {
			if _, ok := u.Secrets[name]; !ok {
				out.Missing = append(out.Missing, name)
			}
		}
		sort.Strings(out.Missing)
	}

	if *asJSON {
		return writeJSON(st, out)
	}
	w := tabwriter.NewWriter(st.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tBACKEND\tALLOWED\tNOTE")
	for _, s := range out.Secrets {
		allow := "any program except shells and interpreters"
		if len(s.Allow) > 0 {
			allow = strings.Join(s.Allow, ", ")
		}
		name := s.Name
		if s.Project {
			name += " *"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, strings.Join(s.Backends, ", "), allow, s.Note)
	}
	_ = w.Flush()
	if out.Project != "" {
		fmt.Fprintf(st.Stdout, "\n* needed by %s\n", out.Project)
	}
	for _, m := range out.Missing {
		fmt.Fprintf(st.Stdout, "missing: the project needs %s; add a [secrets.%s] table to %s\n", m, m, u.Path)
	}
	return ExitOK
}

func writeJSON(st *Streams, v any) int {
	enc := json.NewEncoder(st.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return failf(st, ExitSoftware, "%v", err)
	}
	return ExitOK
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
