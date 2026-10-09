package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/afsharid/passess/internal/detect"
)

func init() {
	commands["list"] = command{"list secret names, their backends and who may receive them", runList}
}

type listedSecret struct {
	Name     string   `json:"name"`
	Backends []string `json:"backends"`
	Refs     []string `json:"refs"`
	Allow    []string `json:"allow"`
	// AllowNone is set for allow = []: no program, where an empty allow
	// alone would read as no list, any program.
	AllowNone bool `json:"allow_none,omitempty"`
	// Clients are the coding agents it is connected to; null means every one.
	Clients  []string `json:"clients"`
	Approve  bool     `json:"approve"`
	Hosts    []string `json:"hosts"`
	Profiles []string `json:"profiles"` // profiles that hand it to a program
	MCP      []string `json:"mcp"`      // MCP servers that use it
	Note     string   `json:"note,omitempty"`
	Project  bool     `json:"needed_by_project"`
}

type listOutput struct {
	Config  string         `json:"config"`
	Project string         `json:"project,omitempty"`
	Secrets []listedSecret `json:"secrets"`
	Missing []string       `json:"missing"` // needed by the project, not defined by the user
	Agents  []listedAgent  `json:"agents"`  // what a clients list may name
}

// listedAgent is an agent a clients list may name. App marks a desktop app
// that reads its own keys: only a list naming it lets one reach it (ADR 11).
type listedAgent struct {
	detect.Agent
	App bool `json:"app,omitempty"`
}

func listedAgents() []listedAgent {
	out := make([]listedAgent, len(detect.Agents))
	for i, a := range detect.Agents {
		out[i] = listedAgent{Agent: a, App: detect.IsApp(a.ID)}
	}
	return out
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
	out := listOutput{Config: u.Path, Secrets: []listedSecret{}, Missing: []string{}, Agents: listedAgents()}
	if proj != nil {
		out.Project = proj.Path
	}
	for _, name := range u.SortedNames() {
		s := u.Secrets[name]
		var backends, refs []string
		for _, r := range s.Refs {
			if !contains(backends, r.Scheme) {
				backends = append(backends, r.Scheme)
			}
			refs = append(refs, r.String())
		}
		_, needed := proj.NeedsName(name)
		ls := listedSecret{Name: name, Backends: backends, Refs: refs, Allow: nonNil(s.Allow), AllowNone: s.Allow != nil && len(s.Allow) == 0, Clients: s.Clients,
			Approve: s.Approve, Hosts: nonNil(s.Hosts), Profiles: []string{}, MCP: []string{}, Note: s.Note, Project: needed}
		for _, p := range sortedKeys(u.Profiles) {
			if contains(u.Profiles[p].Secrets, name) {
				ls.Profiles = append(ls.Profiles, p)
			}
		}
		for _, m := range sortedKeys(u.MCP) {
			if contains(u.MCP[m].Secrets(), name) {
				ls.MCP = append(ls.MCP, m)
			}
		}
		out.Secrets = append(out.Secrets, ls)
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
	fmt.Fprintln(w, "NAME\tBACKEND\tALLOWED\tAGENTS\tNOTE")
	for _, s := range out.Secrets {
		allow := allowedText(u.Secrets[s.Name].Allow, "any program except shells and interpreters")
		name := s.Name
		if s.Project {
			name += " *"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, strings.Join(s.Backends, ", "), allow, agentsText(s.Clients), s.Note)
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

// allowedText says in words who an allow list lets through: anyText for no
// list, "no program" for allow = [], else the programs.
func allowedText(allow []string, anyText string) string {
	switch {
	case allow == nil:
		return anyText
	case len(allow) == 0:
		return "no program"
	}
	return strings.Join(allow, ", ")
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// agentsText says which coding agents a clients list names.
func agentsText(clients []string) string {
	switch {
	case clients == nil:
		return "all"
	case len(clients) == 0:
		return "none"
	}
	return strings.Join(clients, ", ")
}
