package scan

import (
	_ "embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"

	"github.com/afsharid/passess/internal/policy"
)

// gitleaksRules is gitleaks' default rule set, v8.30.1, MIT licensed (see
// rules/LICENSE.gitleaks). It is data here, not code: ADR 5 explains why
// passess does not link gitleaks itself.
//
//go:embed rules/gitleaks.toml
var gitleaksRules []byte

// RulesVersion names the vendored rule set.
const RulesVersion = "gitleaks v8.30.1"

type allowlist struct {
	Regexes     []string `toml:"regexes"`
	RegexTarget string   `toml:"regexTarget"` // "" (the secret), "match" or "line"
	Stopwords   []string `toml:"stopwords"`
	Paths       []string `toml:"paths"`
	Condition   string   `toml:"condition"` // "OR" (default) or "AND"

	regexes []*regexp.Regexp
	paths   []*regexp.Regexp
}

type rule struct {
	ID          string      `toml:"id"`
	Regex       string      `toml:"regex"`
	Keywords    []string    `toml:"keywords"`
	Entropy     float64     `toml:"entropy"`
	SecretGroup int         `toml:"secretGroup"`
	Path        string      `toml:"path"`
	Allowlists  []allowlist `toml:"allowlists"`

	once sync.Once
	re   *regexp.Regexp
	path *regexp.Regexp
	err  error
}

// Rules is a compiled rule set with a keyword prefilter: a rule's own regular
// expression is compiled and run only on lines that contain one of its keywords.
type Rules struct {
	rules     []*rule
	global    allowlist
	keywordRe *regexp.Regexp
	byKeyword map[string][]*rule
	always    []*rule // rules without keywords
}

// DefaultRules parses the vendored gitleaks rules.
func DefaultRules() (*Rules, error) {
	var cfg struct {
		Allowlist allowlist `toml:"allowlist"`
		Rules     []*rule   `toml:"rules"`
	}
	if err := toml.Unmarshal(gitleaksRules, &cfg); err != nil {
		return nil, fmt.Errorf("vendored rules: %w", err)
	}
	rs := &Rules{global: cfg.Allowlist, byKeyword: map[string][]*rule{}}
	if err := rs.global.compile(); err != nil {
		return nil, err
	}
	var keys []string
	for _, r := range cfg.Rules {
		if r.Regex == "" {
			continue // path-only rules flag files by name; passess scans contents
		}
		for i := range r.Allowlists {
			if err := r.Allowlists[i].compile(); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		rs.rules = append(rs.rules, r)
		if len(r.Keywords) == 0 {
			rs.always = append(rs.always, r)
		}
		for _, k := range r.Keywords {
			k = strings.ToLower(k)
			if _, seen := rs.byKeyword[k]; !seen {
				keys = append(keys, regexp.QuoteMeta(k))
			}
			rs.byKeyword[k] = append(rs.byKeyword[k], r)
		}
	}
	rs.keywordRe = regexp.MustCompile(strings.Join(keys, "|"))
	return rs, nil
}

// Len reports how many content rules are loaded.
func (rs *Rules) Len() int { return len(rs.rules) }

func (a *allowlist) compile() error {
	for _, s := range a.Regexes {
		re, err := regexp.Compile(s)
		if err != nil {
			return err
		}
		a.regexes = append(a.regexes, re)
	}
	for _, s := range a.Paths {
		re, err := regexp.Compile(s)
		if err != nil {
			return err
		}
		a.paths = append(a.paths, re)
	}
	return nil
}

func (a *allowlist) allows(path, secret, match, line string) bool {
	var checks []bool
	if len(a.paths) > 0 {
		hit := false
		for _, re := range a.paths {
			hit = hit || re.MatchString(path)
		}
		checks = append(checks, hit)
	}
	if len(a.regexes) > 0 {
		target := secret
		switch a.RegexTarget {
		case "match":
			target = match
		case "line":
			target = line
		}
		hit := false
		for _, re := range a.regexes {
			hit = hit || re.MatchString(target)
		}
		checks = append(checks, hit)
	}
	if len(a.Stopwords) > 0 {
		hit := false
		lower := strings.ToLower(secret)
		for _, w := range a.Stopwords {
			hit = hit || strings.Contains(lower, strings.ToLower(w))
		}
		checks = append(checks, hit)
	}
	if len(checks) == 0 {
		return false
	}
	and := strings.EqualFold(a.Condition, "AND")
	for _, c := range checks {
		if and && !c {
			return false
		}
		if !and && c {
			return true
		}
	}
	return and
}

func (r *rule) compile() error {
	r.once.Do(func() {
		r.re, r.err = regexp.Compile(r.Regex)
		if r.err == nil && r.Path != "" {
			r.path, r.err = regexp.Compile(r.Path)
		}
	})
	return r.err
}

// RuleMatch is a secret-shaped string a rule found on a line.
type RuleMatch struct {
	Rule   string
	Secret string
	Start  int // byte offset of the secret in the line
}

// Line returns the rule matches on one line of path.
func (rs *Rules) Line(path, line string) []RuleMatch {
	if len(line) == 0 {
		return nil
	}
	lower := strings.ToLower(line)
	candidates := map[*rule]bool{}
	for _, r := range rs.always {
		candidates[r] = true
	}
	for _, k := range rs.keywordRe.FindAllString(lower, -1) {
		for _, r := range rs.byKeyword[k] {
			candidates[r] = true
		}
	}
	var out []RuleMatch
	for r := range candidates {
		if r.compile() != nil {
			continue
		}
		if r.path != nil && !r.path.MatchString(path) {
			continue
		}
		for _, idx := range r.re.FindAllStringSubmatchIndex(line, -1) {
			start, end := idx[0], idx[1]
			match := line[start:end]
			sStart, sEnd := start, end
			switch {
			case r.SecretGroup > 0 && 2*r.SecretGroup+1 < len(idx) && idx[2*r.SecretGroup] >= 0:
				sStart, sEnd = idx[2*r.SecretGroup], idx[2*r.SecretGroup+1]
			case r.SecretGroup == 0:
				for g := 1; 2*g+1 < len(idx); g++ {
					if idx[2*g] >= 0 && idx[2*g+1] > idx[2*g] {
						sStart, sEnd = idx[2*g], idx[2*g+1]
						break
					}
				}
			}
			secret := line[sStart:sEnd]
			if r.Entropy > 0 && policy.Entropy(secret) < r.Entropy {
				continue
			}
			if rs.global.allows(path, secret, match, line) {
				continue
			}
			allowed := false
			for i := range r.Allowlists {
				allowed = allowed || r.Allowlists[i].allows(path, secret, match, line)
			}
			if allowed {
				continue
			}
			out = append(out, RuleMatch{Rule: r.ID, Secret: secret, Start: sStart})
		}
	}
	return dedupe(out)
}

// dedupe keeps one match per secret: the specific rule over generic-api-key,
// then the lowest rule id, so output does not depend on map order.
func dedupe(ms []RuleMatch) []RuleMatch {
	type key struct {
		start  int
		secret string
	}
	best := map[key]RuleMatch{}
	var order []key
	for _, m := range ms {
		k := key{m.Start, m.Secret}
		cur, ok := best[k]
		switch {
		case !ok:
			order = append(order, k)
			best[k] = m
		case cur.Rule == "generic-api-key" && m.Rule != "generic-api-key":
			best[k] = m
		case (cur.Rule == "generic-api-key") == (m.Rule == "generic-api-key") && m.Rule < cur.Rule:
			best[k] = m
		}
	}
	sort.Slice(order, func(i, j int) bool { return order[i].start < order[j].start })
	out := make([]RuleMatch, 0, len(order))
	for _, k := range order {
		out = append(out, best[k])
	}
	return out
}
