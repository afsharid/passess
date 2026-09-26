// Package resolve turns configured secrets into values: it tries each
// candidate reference in order through the provider for its scheme and
// returns the first value found.
package resolve

import (
	"context"
	"fmt"
	"strings"

	"github.com/afsharid/passess/internal/config"
	"github.com/afsharid/passess/internal/provider"
	"github.com/afsharid/passess/internal/ref"
	"github.com/afsharid/passess/internal/secret"
)

// Resolver resolves secrets. It remembers values for the life of the process
// so a reference is fetched at most once.
type Resolver struct {
	providers map[string]provider.Provider
	cache     map[string]secret.Value
}

// New returns a Resolver over the given providers.
func New(ps ...provider.Provider) *Resolver {
	r := &Resolver{providers: map[string]provider.Provider{}, cache: map[string]secret.Value{}}
	for _, p := range ps {
		r.providers[p.Scheme()] = p
	}
	return r
}

// MissingError reports a secret none of whose candidates produced a value.
type MissingError struct {
	Name     string
	Attempts []error
}

func (e *MissingError) Error() string {
	var parts []string
	for _, a := range e.Attempts {
		parts = append(parts, a.Error())
	}
	return fmt.Sprintf("%s could not be resolved: %s", e.Name, strings.Join(parts, "; "))
}

// Unwrap exposes the attempts so errors.Is finds ErrUnavailable or ErrNotFound.
func (e *MissingError) Unwrap() []error { return e.Attempts }

// Secret returns the value of s.
func (r *Resolver) Secret(ctx context.Context, s config.Secret) (secret.Value, error) {
	v, _, err := r.SecretFrom(ctx, s)
	return v, err
}

// SecretFrom returns the value of s and the candidate reference it came from.
func (r *Resolver) SecretFrom(ctx context.Context, s config.Secret) (secret.Value, ref.Ref, error) {
	var attempts []error
	for _, rf := range s.Refs {
		v, err := r.Ref(ctx, rf)
		if err != nil {
			attempts = append(attempts, err) // try the next candidate, report all if none works
			continue
		}
		return v, rf, nil
	}
	return secret.Value{}, ref.Ref{}, &MissingError{Name: s.Name, Attempts: attempts}
}

// Ref returns the value one reference points to.
func (r *Resolver) Ref(ctx context.Context, rf ref.Ref) (secret.Value, error) {
	if v, ok := r.cache[rf.String()]; ok {
		return v, nil
	}
	p, ok := r.providers[rf.Scheme]
	if !ok {
		return secret.Value{}, &provider.Error{Ref: rf, Err: fmt.Errorf("%w: %s:// is not supported yet", provider.ErrUnavailable, rf.Scheme)}
	}
	v, err := p.Resolve(ctx, rf)
	if err != nil {
		return secret.Value{}, err
	}
	r.cache[rf.String()] = v
	return v, nil
}

// Cached reports whether the value rf points to is held.
func (r *Resolver) Cached(rf ref.Ref) bool {
	_, ok := r.cache[rf.String()]
	return ok
}

// CachedValue returns the value rf points to, if it is held; no provider is
// asked.
func (r *Resolver) CachedValue(rf ref.Ref) (secret.Value, bool) {
	v, ok := r.cache[rf.String()]
	return v, ok
}

// Available reports, per scheme, whether its provider can be used right now.
func (r *Resolver) Available(ctx context.Context, scheme string) error {
	p, ok := r.providers[scheme]
	if !ok {
		return fmt.Errorf("%w: %s:// is not supported yet", provider.ErrUnavailable, scheme)
	}
	return p.Available(ctx)
}

// Zero overwrites every cached value.
func (r *Resolver) Zero() {
	for k, v := range r.cache {
		v.Zero()
		delete(r.cache, k)
	}
}
