//go:build !darwin && !linux

package agent

import (
	"errors"
	"net"
)

var errUnsupported = errors.New("the passess agent runs on macOS and Linux only")

func peerOf(*net.UnixConn) (Peer, error) { return Peer{}, errUnsupported }

func procInfo(int) (Proc, error) { return Proc{}, errUnsupported }

// Harden is not available on this system.
func Harden() error { return errUnsupported }
