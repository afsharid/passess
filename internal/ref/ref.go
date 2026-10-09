// Package ref parses secret references such as op://vault/item/field.
//
// A reference names where a secret lives; it never contains the secret. Parse
// errors deliberately do not echo their input: a value pasted where a reference
// belongs must not end up in an error message.
package ref

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Schemes supported by passess.
const (
	OnePassword = "op"       // op://vault/item/[section/]field
	BWS         = "bws"      // bws://<secret-uuid> or bws://<project>/<KEY>
	Bitwarden   = "bw"       // bw://<item>/<field>
	Vault       = "vault"    // vault://<mount>/<path>#<key>
	Keychain    = "keychain" // keychain://<service>/<account>
	Env         = "env"      // env://NAME
)

// Ref is a parsed reference.
type Ref struct {
	Scheme string
	Path   []string // segments between "scheme://" and an optional "#key"
	Key    string   // only for vault://
}

// ErrInvalid is wrapped by every parse error.
var ErrInvalid = errors.New("invalid secret reference")

var (
	envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// isControl reports a C0 or C1 control character or DEL: none belongs in a
// reference, and an escape among them would redraw the terminal that shows it.
func isControl(r rune) bool {
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0)
}

// Parse parses s. The error never contains s itself.
func Parse(s string) (Ref, error) {
	scheme, rest, ok := strings.Cut(s, "://")
	if !ok || !known(scheme) {
		return Ref{}, invalid("expected <scheme>://…, one of op, bws, bw, vault, keychain, env")
	}
	if strings.ContainsFunc(rest, isControl) {
		return Ref{}, invalid("%s reference contains a control character", scheme)
	}
	r := Ref{Scheme: scheme}
	if scheme == Vault {
		var key string
		rest, key, ok = strings.Cut(rest, "#")
		if !ok || key == "" {
			return Ref{}, invalid("vault reference needs #<key>")
		}
		r.Key = key
	}
	r.Path = strings.Split(rest, "/")
	for _, seg := range r.Path {
		if seg == "" {
			return Ref{}, invalid("%s reference has an empty path segment", scheme)
		}
	}
	if err := r.validate(); err != nil {
		return Ref{}, err
	}
	return r, nil
}

func known(scheme string) bool {
	switch scheme {
	case OnePassword, BWS, Bitwarden, Vault, Keychain, Env:
		return true
	}
	return false
}

func (r Ref) validate() error {
	n := len(r.Path)
	switch r.Scheme {
	case OnePassword:
		if n < 3 || n > 4 {
			return invalid("op reference is op://vault/item/[section/]field")
		}
	case BWS:
		switch n {
		case 1:
			if !uuidRe.MatchString(r.Path[0]) {
				return invalid("bws reference with one segment must be a secret UUID")
			}
		case 2:
			if !envName.MatchString(r.Path[1]) {
				return invalid("bws reference is bws://<project>/<KEY>, KEY like an env var name")
			}
		default:
			return invalid("bws reference is bws://<uuid> or bws://<project>/<KEY>")
		}
	case Bitwarden:
		if n != 2 {
			return invalid("bw reference is bw://<item>/<field>")
		}
	case Vault:
		if n < 2 {
			return invalid("vault reference is vault://<mount>/<path>#<key>")
		}
	case Keychain:
		if n != 2 {
			return invalid("keychain reference is keychain://<service>/<account>")
		}
	case Env:
		if n != 1 || !envName.MatchString(r.Path[0]) {
			return invalid("env reference is env://NAME")
		}
	default:
		return invalid("unknown scheme; use one of op, bws, bw, vault, keychain, env")
	}
	return nil
}

// String returns the canonical form of the reference.
func (r Ref) String() string {
	s := r.Scheme + "://" + strings.Join(r.Path, "/")
	if r.Key != "" {
		s += "#" + r.Key
	}
	return s
}

// Equal reports whether two references are identical.
func (r Ref) Equal(o Ref) bool { return r.String() == o.String() }
