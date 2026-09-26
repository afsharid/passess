package mcpbridge

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/afsharid/passess/internal/redact"
	"github.com/afsharid/passess/internal/secret"
)

const token = "passess-fake-remote-token-0123456789"

// remote starts a streamable-HTTP MCP server whose only tool echoes the
// Authorization header it was called with — the worst case for a leak.
func remote(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var mu sync.Mutex
	var lastAuth string
	server := mcp.NewServer(&mcp.Implementation{Name: "remote", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "echo the credentials"},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
			mu.Lock()
			defer mu.Unlock()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "you sent " + lastAuth}}}, nil, nil
		})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastAuth = r.Header.Get("Authorization")
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, func() string { mu.Lock(); defer mu.Unlock(); return lastAuth }
}

func TestBridgeAddsHeadersAndRedactsReplies(t *testing.T) {
	ts, lastAuth := remote(t)
	rd, _, err := redact.New([]redact.Secret{{Name: "REMOTE_TOKEN", Value: secret.FromString(token)}}, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), ts.URL, http.Header{"Authorization": {"Bearer " + token}}, inR, outW, rd)
		_ = outW.Close()
	}()
	replies := bufio.NewScanner(outR)
	replies.Buffer(make([]byte, 1<<20), 1<<20)

	send := func(msg string) {
		t.Helper()
		if _, err := io.WriteString(inW, msg+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	next := func() string {
		t.Helper()
		line := make(chan string, 1)
		go func() {
			if replies.Scan() {
				line <- replies.Text()
			} else {
				line <- ""
			}
		}()
		select {
		case l := <-line:
			return l
		case <-time.After(10 * time.Second):
			t.Fatal("no reply from the bridge")
			return ""
		}
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if init := next(); !strings.Contains(init, `"serverInfo"`) {
		t.Fatalf("initialize reply: %s", init)
	}
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	reply := next()

	if got := lastAuth(); got != "Bearer "+token {
		t.Fatalf("server got Authorization %q", got)
	}
	if strings.Contains(reply, token) {
		t.Fatalf("the token reached the harness: %s", reply)
	}
	if !strings.Contains(reply, "you sent Bearer [REDACTED:REMOTE_TOKEN]") {
		t.Fatalf("reply = %s", reply)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(reply), &parsed); err != nil {
		t.Fatalf("redacted reply is not JSON: %v", err)
	}

	_ = inW.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("bridge returned %v after stdin closed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("bridge did not stop when stdin closed")
	}
}
