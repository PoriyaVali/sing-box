package tls

import (
	"context"
	"net"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"

	aTLS "github.com/sagernet/sing/common/tls"
)

// deadlineCapturingConfig implements ServerConfigCompat, which is the branch
// sing takes when the config can handshake itself. It records the context it is
// handed so the test can read the deadline the caller applied - no waiting, and
// it exercises the real ServerHandshake rather than a copy of it.
type deadlineCapturingConfig struct {
	got context.Context
}

func (c *deadlineCapturingConfig) ServerHandshake(ctx context.Context, conn net.Conn) (aTLS.Conn, error) {
	c.got = ctx
	return nil, context.Canceled // stop before any real TLS work
}

func (c *deadlineCapturingConfig) Server(net.Conn) (aTLS.Conn, error) { return nil, context.Canceled }
func (c *deadlineCapturingConfig) Client(net.Conn) (aTLS.Conn, error) { return nil, context.Canceled }
func (c *deadlineCapturingConfig) Start() error                       { return nil }
func (c *deadlineCapturingConfig) Close() error                       { return nil }
func (c *deadlineCapturingConfig) ServerName() string                 { return "" }
func (c *deadlineCapturingConfig) SetServerName(string)               {}
func (c *deadlineCapturingConfig) NextProtos() []string               { return nil }
func (c *deadlineCapturingConfig) SetNextProtos([]string)             {}
func (c *deadlineCapturingConfig) STDConfig() (*STDConfig, error)     { return nil, context.Canceled }
func (c *deadlineCapturingConfig) Clone() aTLS.Config                 { return c }

// 🔴 The inbound handshake must NOT be bounded by the general TCPTimeout.
//
// At 15s it was cutting off real users: TCP retries a lost handshake packet
// with exponential backoff - about 1s, 3s, 7s, 15s - so a client on a network
// dropping one or two packets lands almost exactly on that limit and is dropped
// having already paid the cost of getting that far. It accounted for a quarter
// of all failed handshakes on a production node.
//
// This test fails if anyone points it back at TCPTimeout, which is the obvious
// "simplification" - the two constants look interchangeable and are not.
func TestInboundHandshakeIsNotBoundedByTheGeneralTCPTimeout(t *testing.T) {
	cfg := &deadlineCapturingConfig{}
	_, _ = ServerHandshake(context.Background(), nil, cfg)

	if cfg.got == nil {
		t.Fatal("ServerHandshake never reached the config; the test seam is wrong")
	}
	deadline, ok := cfg.got.Deadline()
	if !ok {
		t.Fatal("no deadline was applied; a silent peer would hold the socket forever")
	}

	budget := time.Until(deadline)
	if budget <= C.TCPTimeout {
		t.Errorf("handshake budget is %v, still bounded by TCPTimeout (%v) - the ceiling is back",
			budget, C.TCPTimeout)
	}
	if budget > C.TLSHandshakeTimeout+time.Second {
		t.Errorf("handshake budget is %v, longer than TLSHandshakeTimeout (%v)",
			budget, C.TLSHandshakeTimeout)
	}
}

// Bounded on purpose. Removing the deadline entirely would let a peer that
// connects and says nothing hold a goroutine and a socket indefinitely, which is
// a cheap way to exhaust a node - and these nodes are probed continuously.
func TestHandshakeBudgetStaysBounded(t *testing.T) {
	if C.TLSHandshakeTimeout <= 0 {
		t.Fatal("an unbounded handshake lets a silent peer pin a socket forever")
	}
	if C.TLSHandshakeTimeout > 2*time.Minute {
		t.Errorf("TLSHandshakeTimeout is %v; that is long enough for held sockets to matter",
			C.TLSHandshakeTimeout)
	}
}

// A caller that already has a shorter deadline must keep it - context.WithTimeout
// takes the earlier of the two, and shutdown paths rely on that.
func TestAShorterCallerDeadlineStillWins(t *testing.T) {
	cfg := &deadlineCapturingConfig{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _ = ServerHandshake(ctx, nil, cfg)

	deadline, ok := cfg.got.Deadline()
	if !ok {
		t.Fatal("no deadline was applied")
	}
	if budget := time.Until(deadline); budget > 3*time.Second {
		t.Errorf("budget is %v; the caller's shorter deadline was overridden", budget)
	}
}
