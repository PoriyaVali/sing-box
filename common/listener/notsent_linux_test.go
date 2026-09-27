package listener

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

type notSentCapture chan net.Conn

func (c notSentCapture) NewConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, _ N.CloseHandlerFunc) {
	c <- conn
}

func acceptOne(t *testing.T, opts option.ListenOptions) net.Conn {
	t.Helper()
	opts.Listen = (*badoption.Addr)(&[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}[0])
	got := make(notSentCapture, 1)
	l := New(Options{
		Context:           context.Background(),
		Logger:            log.NewNOPFactory().NewLogger("test"),
		Network:           []string{N.NetworkTCP},
		Listen:            opts,
		ConnectionHandler: got,
	})
	if err := l.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	c, err := net.Dial("tcp", l.TCPListener().Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	// Some first bytes, as any client sends: with the PROXY-protocol reader on,
	// a peer that sends under a header's worth is held until its timeout.
	c.Write(make([]byte, 32))
	select {
	case conn := <-got:
		t.Cleanup(func() { conn.Close() })
		return conn
	case <-time.After(5 * time.Second):
		t.Fatal("no connection accepted")
	}
	return nil
}

func notSentLowatOf(t *testing.T, c net.Conn) int {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var v int
	raw.Control(func(fd uintptr) { v, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT) })
	return v
}

// Every accepted connection carries tcp_notsent_lowat. It has to be set per
// connection: the kernel does not pass a listener's value on.
func TestListener_TCPNotSentLowatOnAcceptedConnections(t *testing.T) {
	conn := acceptOne(t, option.ListenOptions{TCPNotSentLowat: 16384})
	if v := notSentLowatOf(t, conn); v != 16384 {
		t.Fatalf("accepted connection has TCP_NOTSENT_LOWAT %d, want 16384", v)
	}
}

// Unset, connections are left as the kernel makes them.
func TestListener_TCPNotSentLowatOff(t *testing.T) {
	conn := acceptOne(t, option.ListenOptions{})
	if v := notSentLowatOf(t, conn); v == 16384 {
		t.Fatal("set without being asked for")
	}
}

// With the PROXY-protocol reader on, the option is still set - before the
// connection is handed to the goroutine that sniffs the header.
func TestListener_TCPNotSentLowatWithProxyProtocol(t *testing.T) {
	conn := acceptOne(t, option.ListenOptions{TCPNotSentLowat: 8192, ProxyProtocolAcceptNoHeader: true})
	raw := conn
	if pc, ok := conn.(*proxyProtoConn); ok {
		raw = pc.Conn
	}
	if tc, ok := raw.(*net.TCPConn); !ok {
		t.Skipf("accepted %T", raw)
	} else if v := notSentLowatOf(t, tc); v != 8192 {
		t.Fatalf("TCP_NOTSENT_LOWAT %d, want 8192", v)
	}
}
