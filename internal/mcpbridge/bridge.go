// Package mcpbridge presents a remote streamable-HTTP MCP server to a harness
// as a local stdio server. passess adds the credentials to every request
// itself, so the harness config holds no token, and whatever the server sends
// back passes through the redactor before it reaches the harness.
package mcpbridge

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/afsharid/passess/internal/redact"
)

// headerTransport adds fixed headers to every request.
type headerTransport struct {
	base    http.RoundTripper
	headers http.Header
}

func (t headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, vs := range t.headers {
		r.Header[k] = vs
	}
	return t.base.RoundTrip(r)
}

// Run relays JSON-RPC messages between in/out (the harness) and endpoint until
// either side closes. It returns nil when the harness closes its end.
func Run(ctx context.Context, endpoint string, headers http.Header, in io.ReadCloser, out io.Writer, rd *redact.Redactor) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	w := rd.NewWriter(out)
	down, err := (&mcp.IOTransport{Reader: in, Writer: w}).Connect(ctx)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: headerTransport{base: http.DefaultTransport, headers: headers}}
	up, err := (&mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: client}).Connect(ctx)
	if err != nil {
		_ = down.Close()
		return err
	}

	errc := make(chan error, 2)
	go func() { errc <- pump(ctx, down, up) }() // harness -> server
	go func() { errc <- pump(ctx, up, down) }() // server -> harness
	err = <-errc
	cancel()
	_ = up.Close()
	_ = down.Close()
	<-errc // the other direction stops once its connection closes
	_ = w.Close()
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func pump(ctx context.Context, src, dst mcp.Connection) error {
	for {
		msg, err := src.Read(ctx)
		if err != nil {
			return err
		}
		if err := dst.Write(ctx, msg); err != nil {
			return err
		}
	}
}
