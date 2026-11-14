package agent

import (
	"os"
	"testing"
	"time"
)

type accepted struct {
	c   *Conn
	err error
}

func acceptAsync(l *Listener) <-chan accepted {
	ch := make(chan accepted, 1)
	go func() {
		c, err := l.Accept()
		ch <- accepted{c, err}
	}()
	return ch
}

func waitAccepted(t *testing.T, ch <-chan accepted) *Conn {
	t.Helper()
	select {
	case a := <-ch:
		if a.err != nil {
			t.Fatalf("Accept: %v", a.err)
		}
		t.Cleanup(func() { _ = a.c.Close() })
		return a.c
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return")
	}
	return nil
}

// A client that sends and closes before Accept has no readable peer pid
// (LOCAL_PEERPID fails), so Accept skips it and serves the next client.
func TestAcceptSkipsClientClosedBeforeAccept(t *testing.T) {
	l := listen(t)

	gone, err := Dial(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := gone.Send(Request{V: 1, Kind: "status", Dir: "passess-fake"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}

	ch := acceptAsync(l)
	live, err := Dial(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()

	got := waitAccepted(t, ch)
	if got.Peer.PID != os.Getpid() || got.Peer.UID != os.Getuid() {
		t.Fatalf("Accept returned peer %+v, want this process (pid %d uid %d)", got.Peer, os.Getpid(), os.Getuid())
	}
}

// A live client and a client that only shut down its write side are both
// accepted, with their pid.
func TestAcceptServesLiveAndHalfClosedClients(t *testing.T) {
	l := listen(t)

	for name, halfClose := range map[string]bool{"live": false, "half-closed": true} {
		t.Run(name, func(t *testing.T) {
			ch := acceptAsync(l)
			c, err := Dial(l.Path())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if halfClose {
				if err := c.Send(Request{V: 1, Kind: "status", Dir: "passess-fake"}, nil); err != nil {
					t.Fatal(err)
				}
				if err := c.c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			got := waitAccepted(t, ch)
			if got.Peer.PID != os.Getpid() || got.Peer.UID != os.Getuid() {
				t.Fatalf("Accept returned peer %+v, want pid %d uid %d", got.Peer, os.Getpid(), os.Getuid())
			}
		})
	}
}
