package policy

import (
	"math"
	"net/url"
	"regexp"
	"strings"
)

// Entropy is the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

var tokenPrefixes = regexp.MustCompile(`(?i)^(gh[pousr]_|github_pat_|glpat-|sk-|sk_live_|rk_live_|xox[abprs]-|AKIA|ASIA|AIza|ya29\.|npm_|pypi-|hf_|dop_v1_|shpat_|sq0atp-|figd_|lin_api_|sntrys_|bws_)`)

var reference = regexp.MustCompile(`\$\{|\{\{|\{(env|file):|(^|\s)\$[A-Za-z_]`)

// IsReference reports whether v points at a value held elsewhere (${VAR},
// $VAR, {{NAME}}, {env:VAR}, {file:path}) instead of holding one.
func IsReference(v string) bool { return reference.MatchString(v) }

// SecretHeader reports whether an HTTP header carries a credential: an
// authorization or cookie header, a credential-like name such as X-Api-Key, or
// a value that looks like one.
func SecretHeader(name, value string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie":
		return true
	}
	return Sensitive(strings.ReplaceAll(name, "-", "_")) || LooksLikeSecret(value)
}

// LooksLikeSecret is a conservative test for a credential stored in clear: a
// known token prefix, a URL with a password, or a long, high-entropy string
// that is not a path, a reference or prose. An auth scheme ("Bearer …") is
// looked through.
func LooksLikeSecret(v string) bool {
	v = strings.TrimSpace(v)
	if IsReference(v) {
		return false
	}
	lower := strings.ToLower(v)
	for _, scheme := range []string{"bearer ", "token ", "basic "} {
		if strings.HasPrefix(lower, scheme) {
			v = strings.TrimSpace(v[len(scheme):])
			break
		}
	}
	if tokenPrefixes.MatchString(v) && len(v) >= 12 {
		return true
	}
	if strings.Contains(v, "://") {
		if u, err := url.Parse(v); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				return true // scheme://user:password@host
			}
		}
	}
	if len(v) < 20 || strings.ContainsAny(v, " /\\") {
		return false
	}
	return Entropy(v) >= 3.5
}
