package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Bitwarden resolves bw://<item>/<field> from the Bitwarden Password Manager
// through the bw CLI. The vault must be unlocked: bw reads the session key from
// BW_SESSION, which passess takes from backends.bw.session or its own
// environment and never passes on to anything else.
type Bitwarden struct {
	Runner  Runner
	Getenv  func(string) string
	Session func(ctx context.Context) (secret.Value, error) // nil: BW_SESSION
}

func (Bitwarden) Scheme() string { return ref.Bitwarden }

func (b Bitwarden) getenv(k string) string {
	if b.Getenv != nil {
		return b.Getenv(k)
	}
	return OSGetenv(k)
}

func (b Bitwarden) session(ctx context.Context) (secret.Value, error) {
	if b.Session != nil {
		return b.Session(ctx)
	}
	if s := b.getenv("BW_SESSION"); s != "" {
		return secret.FromString(s), nil
	}
	return secret.Value{}, fmt.Errorf("%w: the Bitwarden vault is locked; set backends.bw.session or unlock with `bw unlock` (passess agent will hold the session later)", ErrUnavailable)
}

func (b Bitwarden) Available(ctx context.Context) error {
	if _, err := lookPath("bw"); err != nil {
		return fmt.Errorf("%w: bw (Bitwarden CLI) is not installed", ErrUnavailable)
	}
	_, err := b.session(ctx)
	return err
}

// Built-in fields bw can return directly; anything else is a custom field.
var bwFields = map[string]bool{"password": true, "username": true, "notes": true, "totp": true, "uri": true}

func (b Bitwarden) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	sess, err := b.session(ctx)
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	env := append(BaseEnv(b.getenv), "BW_SESSION="+string(sess.Bytes()), "BW_NOINTERACTION=true")
	for _, k := range []string{"BITWARDENCLI_APPDATA_DIR", "NODE_EXTRA_CA_CERTS"} {
		if v := b.getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	item, field := r.Path[0], r.Path[1]
	args := []string{"get", field, item}
	if !bwFields[field] {
		args = []string{"get", "item", item}
	}
	res, err := b.Runner.Run(ctx, Cmd{Name: "bw", Args: args, Env: env})
	if err != nil {
		return secret.Value{}, &Error{r, err}
	}
	if res.Exit != 0 {
		clear(res.Stdout)
		return secret.Value{}, &Error{r, classifyBW(res.Stderr, res.Exit)}
	}
	if bwFields[field] {
		v := valueFrom(trimNewline(res.Stdout))
		if v.Empty() {
			return secret.Value{}, &Error{r, ErrNotFound}
		}
		return v, nil
	}
	var it struct {
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"fields"`
	}
	err = json.Unmarshal(res.Stdout, &it)
	clear(res.Stdout)
	if err != nil {
		return secret.Value{}, &Error{r, errors.New("bw returned output passess cannot read")}
	}
	for _, f := range it.Fields {
		if f.Name == field && f.Value != "" {
			return secret.FromString(f.Value), nil
		}
	}
	return secret.Value{}, &Error{r, ErrNotFound}
}

func classifyBW(stderr []byte, exit int) error {
	msg := strings.ToLower(string(stderr))
	switch {
	case strings.Contains(msg, "not found"):
		return ErrNotFound
	case strings.Contains(msg, "more than one result"):
		return errors.New("more than one Bitwarden item matches; use the item id in the reference")
	case strings.Contains(msg, "locked") || strings.Contains(msg, "not logged in") || strings.Contains(msg, "session"):
		return fmt.Errorf("%w: the Bitwarden vault is locked or the session expired: %s", ErrUnavailable, CLIMessage(stderr))
	}
	return fmt.Errorf("bw exited %d: %s", exit, CLIMessage(stderr))
}
