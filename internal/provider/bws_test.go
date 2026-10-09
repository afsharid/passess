package provider

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/afsharid/passess/internal/secret"
)

const (
	fakeToken   = "passess-fake-bws-machine-token-0123456789"
	projectID   = "0b2f6c1e-1d2e-4a5b-9c8d-7e6f5a4b3c2d"
	secretID    = "11111111-2222-4333-8444-555555555555"
	nvidiaValue = "passess-fake-nvidia-0123456789"
)

func bwsFake(t *testing.T) *fakeRunner {
	return &fakeRunner{reply: func(c Cmd) (Result, error) {
		if c.Name != "bws" {
			t.Fatalf("unexpected command %s", c.Name)
		}
		if slices.ContainsFunc(c.Args, func(a string) bool { return strings.Contains(a, fakeToken) }) {
			t.Fatal("the access token must not be in argv")
		}
		if !slices.Contains(c.Env, "BWS_ACCESS_TOKEN="+fakeToken) {
			t.Fatal("the access token must be in the environment")
		}
		switch c.Args[0] + " " + c.Args[1] {
		case "project list":
			return Result{Stdout: []byte(`[{"id":"` + projectID + `","name":"dev-project"}]`)}, nil
		case "secret list":
			if c.Args[2] != projectID {
				return Result{Exit: 1, Stderr: []byte("Error: 404 Not Found")}, nil
			}
			return Result{Stdout: []byte(`[{"id":"` + secretID + `","key":"NVIDIA_API_KEY","value":"` + nvidiaValue + `"},
				{"id":"33333333-2222-4333-8444-555555555555","key":"CHAT_BOT_TOKEN","value":"passess-fake-chat-0123456789"}]`)}, nil
		case "secret get":
			if c.Args[2] == secretID {
				return Result{Stdout: []byte(`{"id":"` + secretID + `","key":"NVIDIA_API_KEY","value":"` + nvidiaValue + `"}`)}, nil
			}
			return Result{Exit: 1, Stderr: []byte("Error: \n   0: Received error message from server: [404 Not Found] {\"message\":\"Resource not found.\"}")}, nil
		}
		t.Fatalf("unexpected bws %q", c.Args)
		return Result{}, nil
	}}
}

func newBWS(run Runner) *BWS {
	return &BWS{Runner: run, ServerURL: "https://vault.example", Token: func(context.Context) (secret.Value, error) {
		return secret.FromString(fakeToken), nil
	}}
}

func TestBWSContract(t *testing.T) {
	contract(t, newBWS(bwsFake(t)), mustRef(t, "bws://dev-project/NVIDIA_API_KEY"), nvidiaValue, mustRef(t, "bws://dev-project/NGC_API_KEY"))
	contract(t, newBWS(bwsFake(t)), mustRef(t, "bws://"+secretID), nvidiaValue, mustRef(t, "bws://99999999-2222-4333-8444-555555555555"))
}

func TestBWSListsAProjectOnce(t *testing.T) {
	run := bwsFake(t)
	b := newBWS(run)
	ctx := context.Background()
	for _, r := range []string{"bws://dev-project/NVIDIA_API_KEY", "bws://dev-project/CHAT_BOT_TOKEN", "bws://" + projectID + "/NVIDIA_API_KEY", "bws://" + secretID} {
		if _, err := b.Resolve(ctx, mustRef(t, r)); err != nil {
			t.Fatalf("%s: %v", r, err)
		}
	}
	var lists, projects, gets int
	for _, c := range run.calls {
		switch c.Args[0] + " " + c.Args[1] {
		case "secret list":
			lists++
		case "project list":
			projects++
		case "secret get":
			gets++
		}
		if !slices.Contains(c.Env, "BWS_SERVER_URL=https://vault.example") {
			t.Fatal("server URL must reach bws")
		}
	}
	if lists != 1 || projects != 1 || gets != 0 {
		t.Fatalf("calls: %d list, %d project list, %d get; want 1, 1, 0", lists, projects, gets)
	}
	b.Zero()
}

func TestBWSWithoutToken(t *testing.T) {
	b := &BWS{Runner: bwsFake(t)}
	_, err := b.Resolve(context.Background(), mustRef(t, "bws://dev-project/NVIDIA_API_KEY"))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "backends.bws.access_token") {
		t.Fatalf("err = %v", err)
	}
}

func TestBWSRejectedToken(t *testing.T) {
	run := &fakeRunner{reply: func(Cmd) (Result, error) {
		return Result{Exit: 1, Stderr: []byte("Error: 401 Unauthorized: invalid access token passess-fake-echoed-0123456789abcdef")}, nil
	}}
	_, err := newBWS(run).Resolve(context.Background(), mustRef(t, "bws://dev-project/NVIDIA_API_KEY"))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "passess-fake-echoed") {
		t.Fatalf("stderr token leaked into the error: %v", err)
	}
}

// Items names every secret the machine account can read and keeps no value:
// the output bws printed them in is cleared.
func TestBWSItemsNamesOnly(t *testing.T) {
	var listed []byte
	run := &fakeRunner{reply: func(c Cmd) (Result, error) {
		switch c.Args[0] + " " + c.Args[1] {
		case "secret list":
			if c.Args[2] != "--output" {
				t.Fatalf("Items lists every project at once, got %q", c.Args)
			}
			listed = []byte(`[{"id":"` + secretID + `","key":"NVIDIA_API_KEY","value":"` + nvidiaValue + `","projectId":"` + projectID + `",
				  "creationDate":"2026-10-09T08:15:23.123456Z"},
				{"id":"44444444-2222-4333-8444-555555555555","key":"loose","value":"passess-fake-loose-0123456789","projectId":null}]`)
			return Result{Stdout: listed}, nil
		case "project list":
			return Result{Stdout: []byte(`[{"id":"` + projectID + `","name":"dev-project"}]`)}, nil
		}
		t.Fatalf("unexpected bws %q", c.Args)
		return Result{}, nil
	}}
	items, err := newBWS(run).Items(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Item{{ID: secretID, Key: "NVIDIA_API_KEY", ProjectID: projectID, Project: "dev-project",
		Created: time.Date(2026, 10, 9, 8, 15, 23, 123456000, time.UTC)},
		{ID: "44444444-2222-4333-8444-555555555555", Key: "loose"}}
	if !slices.Equal(items, want) {
		t.Fatalf("items = %+v", items)
	}
	if strings.Trim(string(listed), "\x00") != "" {
		t.Fatal("the listing that held values was not cleared")
	}
}
