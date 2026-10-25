package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/afsharid/passess/internal/config"
)

// A project's passess.toml names the secrets it uses, never where they come
// from (ADR 3), so editing it hands nothing to anyone: it needs no approval,
// and an agent may do it as it edits the rest of the repository.

func init() {
	commands["needs"] = command{"the secrets a project's passess.toml names: list, add, remove", runNeeds}
}

const needsUsage = `Usage:
  passess needs list [--dir DIR] [--json]
  passess needs add NAME [--note TEXT] [--allow P,Q] [--dir DIR]
  passess needs remove NAME [--dir DIR]
DIR is the project (default: here); the nearest passess.toml at or above it is
used, and add starts one in DIR when there is none.`

// needView is one entry of `needs list --json`.
type needView struct {
	Name    string   `json:"name"`
	Note    string   `json:"note,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Defined bool     `json:"defined"` // your user config maps it to a reference
}

type needsOutput struct {
	Path  string     `json:"path"` // the project file; "" when there is none yet
	Needs []needView `json:"needs"`
}

func runNeeds(st *Streams, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(st.Stderr, needsUsage)
		return ExitUsage
	}
	sub, rest := args[0], args[1:]
	var name string
	if sub == "add" || sub == "remove" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			fmt.Fprintln(st.Stderr, needsUsage)
			return ExitUsage
		}
		name, rest = rest[0], rest[1:]
		if !envNameRe.MatchString(name) {
			return failf(st, ExitUsage, "%q is not a secret name", name)
		}
	}
	fs := flag.NewFlagSet("needs "+sub, flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	fs.Usage = func() { fmt.Fprintln(st.Stderr, needsUsage) }
	dir := fs.String("dir", "", "the project directory (default: here)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	note := fs.String("note", "", "what the project uses it for")
	var allow listFlag
	fs.Var(&allow, "allow", "the programs in the project that may receive it, comma-separated")
	if err := fs.Parse(rest); err != nil || fs.NArg() > 0 {
		return ExitUsage
	}
	if *dir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return failf(st, ExitSoftware, "%v", err)
		}
		*dir = wd
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return failf(st, ExitUsage, "%v", err)
	}
	path := config.FindProject(abs)
	switch sub {
	case "list":
		return listNeeds(st, path, *asJSON)
	case "add":
		if strings.ContainsAny(*note, "\n\r\x00") {
			return failf(st, ExitUsage, "--note must be one line")
		}
		if path == "" {
			path = filepath.Join(abs, config.ProjectFile)
		}
		var fields []config.Field
		if *note != "" {
			q := tomlString(*note)
			fields = append(fields, config.Field{Key: "note", Value: &q})
		}
		if len(allow) > 0 {
			l := arrayLiteral(allow)
			fields = append(fields, config.Field{Key: "allow", Value: &l})
		}
		return editProject(st, path, true, func(data []byte) ([]byte, error) {
			return config.SetTableFields(data, []string{"needs", name}, fields, true)
		}, fmt.Sprintf("%s now names %s", path, name))
	case "remove":
		if path == "" {
			return failf(st, ExitConfig, "no %s at or above %s", config.ProjectFile, abs)
		}
		return editProject(st, path, false, func(data []byte) ([]byte, error) {
			return config.RemoveTable(data, []string{"needs", name})
		}, fmt.Sprintf("%s no longer names %s", path, name))
	}
	fmt.Fprintln(st.Stderr, needsUsage)
	return ExitUsage
}

func listNeeds(st *Streams, path string, asJSON bool) int {
	out := needsOutput{Path: path, Needs: []needView{}}
	if path != "" {
		p, err := config.LoadProject(path)
		if err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
		u, err := loadUserConfig(st)
		if err != nil && !errors.Is(err, config.ErrNoConfig) {
			return failf(st, ExitConfig, "%v", err)
		}
		for _, n := range sortedKeys(p.Needs) {
			v := needView{Name: n, Note: p.Needs[n].Note, Allow: p.Needs[n].Allow}
			if u != nil {
				_, v.Defined = u.Secrets[n]
			}
			out.Needs = append(out.Needs, v)
		}
	}
	if asJSON {
		return writeJSON(st, out)
	}
	if path == "" {
		fmt.Fprintf(st.Stdout, "no %s here; `passess needs add NAME` starts one\n", config.ProjectFile)
		return ExitOK
	}
	fmt.Fprintln(st.Stdout, path)
	for _, n := range out.Needs {
		state := "defined"
		if !n.Defined {
			state = "not in your config: passess add " + n.Name + " --ref …"
		}
		fmt.Fprintf(st.Stdout, "  %-24s %s\n", n.Name, state)
	}
	return ExitOK
}

// editProject rewrites a project file with edit, keeping the result only if
// it still loads; start writes a new one when there is none. It takes no
// lock: a lock file would be left in the user's repository.
func editProject(st *Streams, path string, start bool, edit func([]byte) ([]byte, error), done string) int {
	before, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && start:
		before = []byte("version = 1\n")
	case err != nil:
		return failf(st, ExitConfig, "%v", err)
	default:
		if _, err := config.ParseProject(path, before); err != nil {
			return failf(st, ExitConfig, "%v", err)
		}
	}
	after, err := edit(before)
	if err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	if _, err := config.ParseProject(path, after); err != nil {
		return failf(st, ExitConfig, "the change would leave %s invalid, so it was not made: %v", path, err)
	}
	if err := writeFileAtomic(path, after, 0o644); err != nil {
		return failf(st, ExitConfig, "%v", err)
	}
	fmt.Fprintf(st.Stdout, "%s\n", done)
	return ExitOK
}
