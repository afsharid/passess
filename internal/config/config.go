// Package config loads the user's passess configuration and a project's
// passess.toml.
//
// The user config maps secret names to references and holds all policy. A
// project file may only name the secrets it needs and narrow what may receive
// them (ADR 3). Neither file holds a value; errors show positions and key
// paths, never source lines, in case a value was pasted by mistake.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/afsharid/passess/internal/policy"
	"github.com/afsharid/passess/internal/ref"
)

// ProjectFile is the name of a project's config file.
const ProjectFile = "passess.toml"

// User is the parsed user config.
type User struct {
	Path     string
	Backends Backends
	Secrets  map[string]Secret
	Profiles map[string]Profile
}

// Backends holds per-backend settings.
type Backends struct {
	BWS BWS
}

// BWS configures Bitwarden Secrets Manager.
type BWS struct {
	AccessToken *ref.Ref // where the machine-account token lives, e.g. keychain://passess/bws
	ServerURL   string
}

// Secret is one named secret.
type Secret struct {
	Name  string
	Refs  []ref.Ref // candidates, first that resolves wins
	Allow []string  // program families that may receive it; empty means any non-denied program
	Note  string
}

// Profile is a named bundle for `passess run`.
type Profile struct {
	Name     string
	Secrets  []string
	Required []string
	Allow    []string
	Inherit  []string          // extra variables passed through from the caller
	Env      map[string]string // plain, non-secret values
}

// Project is a parsed project file.
type Project struct {
	Path  string
	Needs map[string]Need
}

// Need is a secret a project uses, optionally narrowed to some programs.
type Need struct {
	Note  string
	Allow []string
}

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type rawUser struct {
	Version  int `toml:"version"`
	Backends struct {
		BWS struct {
			AccessToken string `toml:"access_token"`
			ServerURL   string `toml:"server_url"`
		} `toml:"bws"`
	} `toml:"backends"`
	Secrets map[string]struct {
		Ref   any      `toml:"ref"`
		Allow []string `toml:"allow"`
		Note  string   `toml:"note"`
	} `toml:"secrets"`
	Profiles map[string]struct {
		Secrets  []string          `toml:"secrets"`
		Required []string          `toml:"required"`
		Allow    []string          `toml:"allow"`
		Inherit  []string          `toml:"inherit"`
		Env      map[string]string `toml:"env"`
	} `toml:"profiles"`
}

type rawProject struct {
	Version int `toml:"version"`
	Needs   map[string]struct {
		Note  string   `toml:"note"`
		Allow []string `toml:"allow"`
		Ref   any      `toml:"ref"`
	} `toml:"needs"`
	Secrets any `toml:"secrets"`
}

// UserPath returns where the user config lives: $PASSESS_CONFIG, else
// $XDG_CONFIG_HOME/passess/config.toml, else ~/.config/passess/config.toml.
func UserPath(getenv func(string) string) (string, error) {
	if p := getenv("PASSESS_CONFIG"); p != "" {
		return p, nil
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "passess", "config.toml"), nil
	}
	home := getenv("HOME")
	if home == "" {
		return "", errors.New("cannot locate the user config: HOME is not set")
	}
	return filepath.Join(home, ".config", "passess", "config.toml"), nil
}

// ErrNoConfig is returned when the user config file does not exist.
var ErrNoConfig = errors.New("no passess config")

// LoadUser reads and validates the user config at path.
func LoadUser(path string) (*User, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w at %s; create it with version = 1 and a [secrets.NAME] table holding ref = \"<reference>\"", ErrNoConfig, path)
	}
	if err != nil {
		return nil, err
	}
	var raw rawUser
	if err := decode(path, data, &raw); err != nil {
		return nil, err
	}
	if raw.Version != 1 {
		return nil, fmt.Errorf("%s: version = 1 is required", path)
	}
	u := &User{Path: path, Secrets: map[string]Secret{}, Profiles: map[string]Profile{}}

	if s := raw.Backends.BWS.AccessToken; s != "" {
		r, err := ref.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("%s: backends.bws.access_token: %w", path, err)
		}
		if r.Scheme == ref.BWS {
			return nil, fmt.Errorf("%s: backends.bws.access_token cannot itself live in bws", path)
		}
		u.Backends.BWS.AccessToken = &r
	}
	u.Backends.BWS.ServerURL = raw.Backends.BWS.ServerURL

	for name, s := range raw.Secrets {
		if !nameRe.MatchString(name) {
			return nil, fmt.Errorf("%s: secrets.%s: a secret name must look like an environment variable name", path, name)
		}
		refs, err := parseRefs(s.Ref)
		if err != nil {
			return nil, fmt.Errorf("%s: secrets.%s.ref: %w", path, name, err)
		}
		allow, err := programs(s.Allow)
		if err != nil {
			return nil, fmt.Errorf("%s: secrets.%s.allow: %w", path, name, err)
		}
		u.Secrets[name] = Secret{Name: name, Refs: refs, Allow: allow, Note: s.Note}
	}

	for name, p := range raw.Profiles {
		if !nameRe.MatchString(strings.ReplaceAll(name, "-", "_")) {
			return nil, fmt.Errorf("%s: profiles.%s: invalid profile name", path, name)
		}
		for _, list := range [][]string{p.Secrets, p.Required} {
			for _, s := range list {
				if _, ok := u.Secrets[s]; !ok {
					return nil, fmt.Errorf("%s: profiles.%s uses %s, which is not defined under [secrets]", path, name, s)
				}
			}
		}
		for _, s := range p.Required {
			if !contains(p.Secrets, s) {
				return nil, fmt.Errorf("%s: profiles.%s.required lists %s, which is not in its secrets", path, name, s)
			}
		}
		allow, err := programs(p.Allow)
		if err != nil {
			return nil, fmt.Errorf("%s: profiles.%s.allow: %w", path, name, err)
		}
		if len(allow) == 0 {
			return nil, fmt.Errorf("%s: profiles.%s.allow: a profile must name the programs it runs", path, name)
		}
		for _, v := range p.Inherit {
			if !nameRe.MatchString(v) {
				return nil, fmt.Errorf("%s: profiles.%s.inherit: %q is not a variable name", path, name, v)
			}
		}
		for k := range p.Env {
			if !nameRe.MatchString(k) {
				return nil, fmt.Errorf("%s: profiles.%s.env: %q is not a variable name", path, name, k)
			}
			if policy.Sensitive(k) {
				return nil, fmt.Errorf("%s: profiles.%s.env.%s looks like a credential; define it under [secrets] and list it in the profile", path, name, k)
			}
		}
		u.Profiles[name] = Profile{Name: name, Secrets: p.Secrets, Required: p.Required, Allow: allow, Inherit: p.Inherit, Env: p.Env}
	}
	return u, nil
}

// LoadProject reads a project file.
func LoadProject(path string) (*Project, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw rawProject
	if err := decode(path, data, &raw); err != nil {
		return nil, err
	}
	if raw.Version != 1 {
		return nil, fmt.Errorf("%s: version = 1 is required", path)
	}
	if raw.Secrets != nil {
		return nil, fmt.Errorf("%s: a project file cannot define [secrets]; list names under [needs] and map them in your user config", path)
	}
	p := &Project{Path: path, Needs: map[string]Need{}}
	for name, n := range raw.Needs {
		if !nameRe.MatchString(name) {
			return nil, fmt.Errorf("%s: needs.%s: invalid secret name", path, name)
		}
		if n.Ref != nil {
			return nil, fmt.Errorf("%s: needs.%s.ref: a project file cannot hold references; map %s in your user config", path, name, name)
		}
		allow, err := programs(n.Allow)
		if err != nil {
			return nil, fmt.Errorf("%s: needs.%s.allow: %w", path, name, err)
		}
		p.Needs[name] = Need{Note: n.Note, Allow: allow}
	}
	return p, nil
}

// FindProject walks up from dir and returns the nearest project file, or "".
func FindProject(dir string) string {
	for {
		p := filepath.Join(dir, ProjectFile)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// ProjectAllow returns the project's narrowing for name, or nil.
func (p *Project) ProjectAllow(name string) []string {
	if p == nil {
		return nil
	}
	return p.Needs[name].Allow
}

// SortedNames returns the secret names in order.
func (u *User) SortedNames() []string {
	names := make([]string, 0, len(u.Secrets))
	for n := range u.Secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func decode(path string, data []byte, v any) error {
	dec := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		return nil
	}
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		var keys []string
		for _, e := range strict.Errors {
			keys = append(keys, strings.Join(e.Key(), "."))
		}
		return fmt.Errorf("%s: unknown key(s): %s", path, strings.Join(keys, ", "))
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, col := de.Position()
		return fmt.Errorf("%s:%d:%d: invalid TOML", path, row, col)
	}
	return fmt.Errorf("%s: invalid config", path)
}

func parseRefs(v any) ([]ref.Ref, error) {
	var in []string
	switch t := v.(type) {
	case nil:
		return nil, errors.New("missing; set ref = \"op://…\" or a list of candidates")
	case string:
		in = []string{t}
	case []any:
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, errors.New("every candidate must be a string")
			}
			in = append(in, s)
		}
	default:
		return nil, errors.New("must be a string or a list of strings")
	}
	if len(in) == 0 {
		return nil, errors.New("empty candidate list")
	}
	refs := make([]ref.Ref, 0, len(in))
	for i, s := range in {
		r, err := ref.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("candidate %d: %w", i+1, err)
		}
		refs = append(refs, r)
	}
	return refs, nil
}

func programs(list []string) ([]string, error) {
	for _, p := range list {
		if p == "" || strings.ContainsAny(p, "/ \t") {
			return nil, fmt.Errorf("%q: list program names, not paths or command lines", p)
		}
	}
	return list, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
