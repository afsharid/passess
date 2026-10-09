package cli

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/resolve"
)

func init() {
	commands["discover"] = command{"list the secrets in your vault that passess does not use yet, by name only", runDiscover}
}

// discoverRunner runs the vault CLIs discover asks; tests replace it.
var discoverRunner provider.Runner = provider.ExecRunner{}

// discovered is a vault secret passess has no reference to, with the name
// and reference `passess add` would take. It never holds a value.
type discovered struct {
	Key       string `json:"key"`     // its name in the vault
	Project   string `json:"project"` // the vault project's name, "" for none
	Name      string `json:"name"`    // a passess name for it
	Ref       string `json:"ref"`
	NameTaken bool   `json:"name_taken"`        // a passess secret already has that name
	Created   string `json:"created,omitempty"` // when it was added to the vault, RFC 3339
}

type discoverBackend struct {
	Scheme string `json:"scheme"`
	OK     bool   `json:"ok"`
	// State says why it is not OK where the app acts on it: "not-set-up"
	// when no token is stored anywhere passess looks.
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

// backendNotSetUp is the State of a backend with no credential at all.
const backendNotSetUp = "not-set-up"

type discoverOutput struct {
	Backends []discoverBackend `json:"backends"`
	Secrets  []discovered      `json:"secrets"`
}

func runDiscover(st *Streams, args []string) int {
	fs := flag.NewFlagSet("discover", flag.ContinueOnError)
	fs.SetOutput(st.Stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		fmt.Fprintln(st.Stderr, "Usage: passess discover [--json]")
		return ExitUsage
	}
	// The vault's inventory is the user's to see, like its values.
	if code := refuseUnderAgent(st, "discover", "lists what your vault holds"); code != 0 {
		return code
	}
	u, _, code := loadConfig(st)
	if code != 0 {
		return code
	}
	out := discoverOutput{Backends: []discoverBackend{}, Secrets: []discovered{}}
	boot := resolve.New(newBootProviders(st)...)
	defer boot.Zero()
	bws := &provider.BWS{Runner: discoverRunner, Getenv: st.Getenv, ServerURL: u.Backends.BWS.ServerURL, Token: bwsToken(st, u, boot)}
	defer bws.Zero()

	code = ExitOK
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	items, err := bws.Items(ctx)
	cancel()
	switch {
	case errors.Is(err, errNoBWSToken): // not set up is a state, not a failure
		out.Backends = append(out.Backends, discoverBackend{Scheme: ref.BWS, State: backendNotSetUp, Error: err.Error()})
	case err != nil:
		out.Backends = append(out.Backends, discoverBackend{Scheme: ref.BWS, Error: err.Error()})
		code = resolveExitCode(err)
	default:
		out.Backends = append(out.Backends, discoverBackend{Scheme: ref.BWS, OK: true})
		out.Secrets = unreferenced(u.Secrets, items)
	}

	if *asJSON {
		if c := writeJSON(st, out); c != 0 {
			return c
		}
		return code
	}
	for _, b := range out.Backends {
		if !b.OK {
			fmt.Fprintf(st.Stderr, "passess: %s: %s\n", b.Scheme, b.Error)
		}
	}
	if len(out.Secrets) == 0 {
		if code == ExitOK {
			fmt.Fprintln(st.Stdout, "passess uses every secret it can see in your vault")
		}
		return code
	}
	w := tabwriter.NewWriter(st.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IN THE VAULT\tPROJECT\tADD WITH")
	for _, d := range out.Secrets {
		// Whoever can write to the vault chooses these names; an escape
		// sequence in one must not redraw the table the user reads.
		fmt.Fprintf(w, "%s\t%s\tpassess add %s --ref %s\n", vaultName(d.Key), vaultName(d.Project), d.Name, vaultName(d.Ref))
	}
	_ = w.Flush()
	fmt.Fprintln(st.Stdout, "\nOr connect them in Passess.app.")
	return code
}

// vaultName is a name from the vault fit for one table cell: printable, no tab.
func vaultName(s string) string {
	return printable(strings.ReplaceAll(s, "\t", " "))
}

// unreferenced returns the items no configured secret refers to, each with a
// name and a reference to add it by: bws://<project-id>/<KEY> when the key is
// one a reference can name and unique in its project, else bws://<uuid>.
func unreferenced(secrets map[string]config.Secret, items []provider.Item) []discovered {
	projectID := map[string]string{} // name -> id
	count := map[string]int{}        // project id/key -> items
	for _, it := range items {
		if it.Project != "" {
			projectID[it.Project] = it.ProjectID
		}
		count[strings.ToLower(it.ProjectID)+"/"+it.Key]++
	}
	ids, keys := map[string]bool{}, map[string]bool{}
	for _, s := range secrets {
		for _, r := range s.Refs {
			if r.Scheme != ref.BWS {
				continue
			}
			switch len(r.Path) {
			case 1:
				ids[strings.ToLower(r.Path[0])] = true
			case 2:
				p := r.Path[0]
				if id, ok := projectID[p]; ok {
					p = id
				}
				keys[strings.ToLower(p)+"/"+r.Path[1]] = true
			}
		}
	}
	out := []discovered{}
	for _, it := range items {
		key := strings.ToLower(it.ProjectID) + "/" + it.Key
		if ids[strings.ToLower(it.ID)] || keys[key] {
			continue
		}
		d := discovered{Key: it.Key, Project: it.Project, Name: suggestName(it.Key), Ref: "bws://" + it.ID}
		if !it.Created.IsZero() {
			d.Created = it.Created.UTC().Format(time.RFC3339)
		}
		if it.ProjectID != "" && envNameRe.MatchString(it.Key) && count[key] == 1 {
			d.Ref = "bws://" + it.ProjectID + "/" + it.Key
		}
		_, d.NameTaken = secrets[d.Name]
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b discovered) int {
		return cmp.Or(cmp.Compare(a.Project, b.Project), cmp.Compare(a.Key, b.Key))
	})
	return out
}

// suggestName turns a vault key into an environment variable name:
// "nvidia-nim" becomes NVIDIA_NIM.
func suggestName(key string) string {
	name := identifier(key)
	if !envNameRe.MatchString(name) {
		name = strings.Trim("SECRET_"+name, "_")
	}
	return name
}
