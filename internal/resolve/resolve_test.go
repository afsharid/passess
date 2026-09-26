package resolve

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

type countingEnv struct {
	provider.Env
	calls int
}

func (c *countingEnv) Resolve(ctx context.Context, r ref.Ref) (secret.Value, error) {
	c.calls++
	return c.Env.Resolve(ctx, r)
}

func refs(t *testing.T, ss ...string) []ref.Ref {
	var out []ref.Ref
	for _, s := range ss {
		r, err := ref.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func TestFirstCandidateThatResolvesWins(t *testing.T) {
	env := map[string]string{"SECOND": "passess-fake-second-0123456789"}
	p := &countingEnv{Env: provider.Env{Lookup: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}}
	r := New(p)
	s := config.Secret{Name: "S", Refs: refs(t, "env://FIRST", "env://SECOND")}
	v, err := r.Secret(context.Background(), s)
	if err != nil || string(v.Bytes()) != env["SECOND"] {
		t.Fatalf("got err %v", err)
	}
	calls := p.calls
	if _, err := r.Secret(context.Background(), config.Secret{Name: "S2", Refs: refs(t, "env://SECOND")}); err != nil {
		t.Fatal(err)
	}
	if p.calls != calls {
		t.Fatal("a resolved reference must come from the cache")
	}
	r.Zero()
	if !v.Empty() {
		t.Fatal("Zero must clear cached values")
	}
}

func TestMissingReportsEveryCandidate(t *testing.T) {
	r := New(provider.Env{Lookup: func(string) (string, bool) { return "", false }})
	_, err := r.Secret(context.Background(), config.Secret{Name: "S", Refs: refs(t, "env://A", "op://v/i/f")})
	var miss *MissingError
	if !errors.As(err, &miss) || len(miss.Attempts) != 2 {
		t.Fatalf("err = %v", err)
	}
	if !errors.Is(err, provider.ErrNotFound) || !errors.Is(err, provider.ErrUnavailable) {
		t.Fatalf("both causes must be visible: %v", err)
	}
	if !strings.Contains(err.Error(), "env://A") || !strings.Contains(err.Error(), "op://v/i/f") {
		t.Fatalf("error must name the references: %v", err)
	}
}
