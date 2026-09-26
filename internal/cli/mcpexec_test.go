package cli

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpValue = "passess-fake-mcp-token-0123456789"

// A stdio "server" that answers one request with what it can see: the line it
// read, the injected secret and a variable it must not have inherited.
const echoServer = `read line; printf '{"jsonrpc":"2.0","id":1,"result":{"seen":%s,"token":"%s","leaked":"%s"}}\n' "$line" "$TOKEN_VAR" "$UNRELATED_API_KEY"`

func setupMCP(t *testing.T, extra string) {
	t.Helper()
	writeConfig(t, `version = 1
[secrets.X]
ref = "env://PASSESS_TEST_MCP_TOKEN"
[secrets.GH_ONLY]
ref   = "env://PASSESS_TEST_MCP_TOKEN"
allow = ["gh"]

[mcp.echo]
command = ["sh", "-c", '''`+echoServer+`''']
env     = { TOKEN_VAR = "X" }

[mcp.picky]
command = ["sh", "-c", "true"]
env     = { T = "GH_ONLY" }
`+extra)
	t.Setenv("PASSESS_TEST_MCP_TOKEN", mcpValue)
	t.Setenv("UNRELATED_API_KEY", "passess-fake-unrelated-0123456789")
}

func TestMCPExecLocalServer(t *testing.T) {
	setupMCP(t, "")
	var out, errb bytes.Buffer
	code := Main([]string{"mcp-exec", "echo"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	got := out.String()
	if strings.Contains(got, mcpValue) {
		t.Fatalf("the secret reached the harness: %s", got)
	}
	for _, want := range []string{`"token":"[REDACTED:X]"`, `"leaked":""`, `"method":"ping"`} {
		if !strings.Contains(got, want) {
			t.Fatalf("reply lacks %s: %s", want, got)
		}
	}
}

func TestMCPExecRefusals(t *testing.T) {
	setupMCP(t, "")
	if _, errOut, code := run(t, "mcp-exec", "picky"); code != ExitNoPerm || !strings.Contains(errOut, "GH_ONLY") {
		t.Fatalf("allow list ignored: exit %d: %s", code, errOut)
	}
	if _, _, code := run(t, "mcp-exec", "nope"); code != ExitConfig {
		t.Fatalf("unknown server: exit %d", code)
	}
	if _, _, code := run(t, "mcp-exec", "echo", "--", "sh", "-c", "env"); code != ExitUsage {
		t.Fatalf("extra argv accepted: exit %d", code)
	}
}

func TestMCPExecRemoteServer(t *testing.T) {
	var mu sync.Mutex
	var auth string
	server := mcp.NewServer(&mcp.Implementation{Name: "remote", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Name: "whoami"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		mu.Lock()
		defer mu.Unlock()
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "you sent " + auth}}}, nil, nil
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = r.Header.Get("Authorization")
		mu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer ts.Close()

	setupMCP(t, "[mcp.remote]\nurl = \""+ts.URL+"/mcp\"\nheaders = { Authorization = \"Bearer {{X}}\" }\n")
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- Main([]string{"mcp-exec", "remote"}, inR, outW, &errb)
		_ = outW.Close()
	}()
	lines := bufio.NewScanner(outR)
	next := func() string {
		got := make(chan string, 1)
		go func() {
			lines.Scan()
			got <- lines.Text()
		}()
		select {
		case l := <-got:
			return l
		case <-time.After(10 * time.Second):
			t.Fatalf("no reply; stderr %q", errb.String())
			return ""
		}
	}
	send := func(msg string) {
		if _, err := io.WriteString(inW, msg+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	next()
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	reply := next()
	if strings.Contains(reply, mcpValue) || !strings.Contains(reply, "you sent Bearer [REDACTED:X]") {
		t.Fatalf("reply = %s", reply)
	}
	mu.Lock()
	sent := auth
	mu.Unlock()
	if sent != "Bearer "+mcpValue {
		t.Fatalf("the server got Authorization %q", sent)
	}
	_ = inW.Close()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
}
