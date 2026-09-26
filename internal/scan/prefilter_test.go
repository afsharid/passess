package scan

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
)

// byContains is the plainest prefilter: every rule whose keyword appears
// anywhere in the line, found by strings.Contains, runs over the line. Line's
// one-pass prefilter must choose the same rules.
func byContains(rs *Rules, path, line string) []RuleMatch {
	lower := strings.ToLower(line)
	var out []RuleMatch
	for _, r := range rs.rules {
		hit := len(r.Keywords) == 0
		for _, k := range r.Keywords {
			hit = hit || strings.Contains(lower, strings.ToLower(k))
		}
		if !hit || r.compile() != nil || (r.path != nil && !r.path.MatchString(path)) {
			continue
		}
		for _, idx := range r.re.FindAllStringSubmatchIndex(line, -1) {
			if m, ok := rs.accept(r, path, line, idx); ok {
				out = append(out, m)
			}
		}
	}
	return dedupe(out)
}

// samples are token-shaped strings of several rules, built at run time.
func samples(rng *rand.Rand) []string {
	alnum := func(n int, set string) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = set[rng.IntN(len(set))]
		}
		return string(b)
	}
	const mixed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	jwt := func() string {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s","iat":%d}`, alnum(12, mixed), rng.IntN(1e9))))
		return h + "." + p + "." + alnum(43, mixed)
	}
	key := func() string {
		body := make([]string, 25)
		for i := range body {
			body[i] = alnum(64, mixed+"+/")
		}
		return "-----BEGIN RSA PRIVATE KEY-----\\n" + strings.Join(body, "\\n") + "\\n-----END RSA PRIVATE KEY-----"
	}
	return []string{
		"gh" + "p_" + alnum(36, mixed),
		"glp" + "at-" + alnum(20, mixed),
		"xox" + "b-" + alnum(12, "0123456789") + "-" + alnum(13, "0123456789") + "-" + alnum(24, mixed),
		"AK" + "IA" + alnum(16, upper),
		"AI" + "za" + "Sy" + alnum(33, mixed),
		"sk_" + "live_" + alnum(24, mixed),
		`api_key = "` + alnum(32, mixed) + `"`,
		"np" + "m_" + alnum(36, mixed),
		"SG" + "." + alnum(22, mixed) + "." + alnum(43, mixed),
		jwt(),
		key(),
	}
}

func filler(rng *rand.Rand, n int) string {
	words := []string{"the", "token", "key", "secret", "auth", "password", "config", "value", "api", "user",
		"{", "}", `"`, ":", ",", "=", "\\n", " ", " ", " ", "0x1f", "id", "session", "bearer", "access"}
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[rng.IntN(len(words))])
	}
	return b.String()
}

func key(m RuleMatch) string { return fmt.Sprintf("%s|%d|%s", m.Rule, m.Start, m.Secret) }

func keys(ms []RuleMatch) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = key(m)
	}
	sort.Strings(out)
	return out
}

func TestKeywordPrefilterMissesNothing(t *testing.T) {
	rs := rules(t)
	rng := rand.New(rand.NewPCG(1, 2))
	found := 0
	for i := 0; i < 160; i++ {
		size := []int{80, 600, 2000, 6000}[i%4]
		line := filler(rng, size)
		for j := rng.IntN(4); j > 0; j-- {
			s := samples(rng)[rng.IntN(11)]
			at := rng.IntN(len(line) + 1)
			line = line[:at] + " " + s + " " + line[at:]
		}
		got, want := keys(rs.Line("x.txt", line)), keys(byContains(rs, "x.txt", line))
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("line %d (%d bytes): the prefilter found\n%v\nstrings.Contains found\n%v", i, len(line), got, want)
		}
		found += len(got)
	}
	if found < 100 {
		t.Fatalf("only %d matches across the test lines; the samples are not exercising the rules", found)
	}
}

func TestKeywordsInsideKeywords(t *testing.T) {
	rs := rules(t)
	line := "administrator_login_password = " + `"` + "Zq8Xw2Lm9P" + "v4Rt7YkB3nC6sD1fG5hJ0a" + `"`
	if got, want := keys(rs.Line("x.txt", line)), keys(byContains(rs, "x.txt", line)); strings.Join(got, ",") != strings.Join(want, ",") || len(got) == 0 {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func BenchmarkLongTranscriptLine(b *testing.B) {
	rs, err := DefaultRules()
	if err != nil {
		b.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(3, 4))
	line := filler(rng, 1<<20) // a 1 MB JSONL line full of "key" and "token"
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		rs.Line("t.jsonl", line)
	}
}
