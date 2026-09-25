package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// BWS resolves bws://<secret-uuid> and bws://<project>/<KEY> through the
// Bitwarden Secrets Manager CLI. The machine-account token reaches bws in its
// environment, never on the command line.
//
// A project is listed once per process: resolving N keys of one project
// costs one `bws secret list`.
type BWS struct {
	Runner    Runner
	Getenv    func(string) string
	ServerURL string
	// Token returns the machine-account access token.
	Token func(ctx context.Context) (secret.Value, error)

	token    secret.Value
	projects map[string]string            // project name -> id
	lists    map[string]map[string][]byte // project id -> key -> value
	byID     map[string][]byte            // secret id -> value, from lists and gets
	listed   map[string]bool
}

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func (*BWS) Scheme() string { return ref.BWS }

func (b *BWS) Available(ctx context.Context) error {
	_, err := b.accessToken(ctx)
	return err
}

func (b *BWS) accessToken(ctx context.Context) (secret.Value, error) {
	if !b.token.Empty() {
		return b.token, nil
	}
	if b.Token == nil {
		return secret.Value{}, fmt.Errorf("%w: no bws access token; set backends.bws.access_token (for example \"keychain://passess/bws\") and store the machine token with `security add-generic-password -U -s passess -a bws -w`", ErrUnavailable)
	}
	v, err := b.Token(ctx)
	if err != nil {
		return secret.Value{}, fmt.Errorf("%w: bws access token: %w", ErrUnavailable, err)
	}
	b.token = v
	return v, nil
}

func (b *BWS) run(ctx context.Context, args ...string) ([]byte, error) {
	tok, err := b.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	getenv := b.Getenv
	if getenv == nil {
		getenv = OSGetenv
	}
	env := append(BaseEnv(getenv), "BWS_ACCESS_TOKEN="+string(tok.Bytes()))
	if b.ServerURL != "" {
		env = append(env, "BWS_SERVER_URL="+b.ServerURL)
	}
	res, err := b.Runner.Run(ctx, Cmd{Name: "bws", Args: append(args, "--output", "json", "--color", "no"), Env: env})
	if err != nil {
		return nil, err
	}
	if res.Exit != 0 {
		clear(res.Stdout)
		return nil, classifyBWS(res.Stderr, res.Exit)
	}
	return res.Stdout, nil
}

func classifyBWS(stderr []byte, exit int) error {
	msg := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(msg, "404") || strings.Contains(msg, "not found"):
		return ErrNotFound
	case strings.Contains(msg, "401") || strings.Contains(msg, "403") || strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "access token") || strings.Contains(msg, "forbidden"):
		return fmt.Errorf("%w: bws rejected the access token: %s", ErrUnavailable, CLIMessage(stderr))
	}
	return fmt.Errorf("bws exited %d: %s", exit, CLIMessage(stderr))
}

type bwsSecret struct {
	ID    string `json:"id"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

func (b *BWS) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	if b.byID == nil {
		b.projects, b.lists, b.byID, b.listed = map[string]string{}, map[string]map[string][]byte{}, map[string][]byte{}, map[string]bool{}
	}
	if len(r.Path) == 1 {
		return b.getByID(ctx, r)
	}
	project, key := r.Path[0], r.Path[1]
	id, err := b.projectID(ctx, project)
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	if err := b.list(ctx, id); err != nil {
		return secret.Value{}, &Error{r, err}
	}
	v, ok := b.lists[id][key]
	if !ok || len(v) == 0 {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	return secret.New(v), nil
}

func (b *BWS) getByID(ctx context.Context, r ref.Ref) (secret.Value, error) {
	id := r.Path[0]
	if v, ok := b.byID[id]; ok {
		return secret.New(v), nil
	}
	out, err := b.run(ctx, "secret", "get", id)
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	var s bwsSecret
	err = json.Unmarshal(out, &s)
	clear(out)
	if err != nil {
		return secret.Value{}, &Error{r, errors.New("bws returned output passess cannot read")}
	}
	if s.Value == "" {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	b.byID[id] = []byte(s.Value)
	return secret.FromString(s.Value), nil
}

func (b *BWS) projectID(ctx context.Context, project string) (string, error) {
	if uuidPattern.MatchString(project) {
		return project, nil
	}
	if id, ok := b.projects[project]; ok {
		return id, nil
	}
	out, err := b.run(ctx, "project", "list")
	if err != nil {
		return "", err
	}
	var ps []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &ps); err != nil {
		return "", errors.New("bws returned output passess cannot read")
	}
	for _, p := range ps {
		b.projects[p.Name] = p.ID
	}
	id, ok := b.projects[project]
	if !ok {
		return "", fmt.Errorf("%w: no bws project named %q visible to this machine account", ErrNotFound, project)
	}
	return id, nil
}

func (b *BWS) list(ctx context.Context, projectID string) error {
	if b.listed[projectID] {
		return nil
	}
	out, err := b.run(ctx, "secret", "list", projectID)
	if err != nil {
		return err
	}
	var ss []bwsSecret
	err = json.Unmarshal(out, &ss)
	clear(out)
	if err != nil {
		return errors.New("bws returned output passess cannot read")
	}
	keys := map[string][]byte{}
	for _, s := range ss {
		keys[s.Key] = []byte(s.Value)
		b.byID[s.ID] = keys[s.Key]
	}
	b.lists[projectID], b.listed[projectID] = keys, true
	return nil
}

// Zero clears the token and every value the provider holds.
func (b *BWS) Zero() {
	b.token.Zero()
	for _, keys := range b.lists {
		for _, v := range keys {
			clear(v)
		}
	}
	for _, v := range b.byID {
		clear(v)
	}
	b.lists, b.byID, b.listed = nil, nil, nil
}
