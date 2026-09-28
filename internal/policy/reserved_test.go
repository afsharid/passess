package policy

import "testing"

// The passess-helper opt-in never authorizes a program, even one named
// passess-helper, through Check or CheckConfigured.
func TestReservedFamilyIsNotAProgram(t *testing.T) {
	p := Program{Typed: "passess-helper", Path: "/tmp/passess-helper", Name: "passess-helper", Families: []string{"passess-helper"}}
	for _, allow := range [][]string{{ReservedFamily}, {"passess-helper"}} {
		if d := Check("TOKEN", p, allow); d.Allowed {
			t.Fatalf("Check allowed %v under %v", p.Name, allow)
		}
		if d := CheckConfigured("TOKEN", p, allow); d.Allowed {
			t.Fatalf("CheckConfigured allowed %v under %v", p.Name, allow)
		}
	}
	// A real program next to the opt-in is still allowed.
	gh := Program{Typed: "gh", Path: "/usr/bin/gh", Name: "gh", Families: []string{"gh"}}
	if d := Check("TOKEN", gh, []string{ReservedFamily, "gh"}); !d.Allowed {
		t.Fatalf("gh refused: %s", d.Reason)
	}
}
