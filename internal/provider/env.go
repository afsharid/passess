package provider

import (
	"context"
	"os"

	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Env resolves env://NAME from passess's own environment.
type Env struct {
	Lookup func(string) (string, bool) // os.LookupEnv when nil
}

func (Env) Scheme() string                  { return ref.Env }
func (Env) Available(context.Context) error { return nil }

func (e Env) Resolve(_ context.Context, r ref.Ref) (secret.Value, error) {
	lookup := e.Lookup
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(r.Path[0])
	if !ok || v == "" {
		return secret.Value{}, &Error{r, ErrNotFound}
	}
	return secret.FromString(v), nil
}
