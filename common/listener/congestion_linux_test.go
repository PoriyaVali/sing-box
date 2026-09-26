package listener

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func congestionOf(t *testing.T, c net.Conn) string {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	raw.Control(func(fd uintptr) {
		name, _ = unix.GetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION)
	})
	return strings.TrimRight(name, "\x00")
}

// Connections accepted by a listener with tcp_congestion inherit it, without
// touching the system default. Needs a kernel with bbr and CAP_NET_ADMIN (root)
// to load it; otherwise it is skipped rather than failed.
func TestListener_TCPCongestionIsInherited(t *testing.T) {
	avail, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if os.Geteuid() != 0 && !strings.Contains(string(avail), "bbr") {
		t.Skip("bbr not loaded and not root")
	}
	l := New(Options{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().NewLogger("test"),
		Network: []string{N.NetworkTCP},
		Listen: option.ListenOptions{
			Listen:        (*badoption.Addr)(&[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}[0]),
			TCPCongestion: "bbr",
		},
	})
	ln, err := l.ListenTCP()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("no connection accepted")
	}
	defer server.Close()
	for server != nil {
		if tc, ok := server.(*net.TCPConn); ok {
			server = tc
			break
		}
		u, ok := server.(interface{ NetConn() net.Conn })
		if !ok {
			t.Fatalf("cannot reach the TCP socket under %T", server)
		}
		server = u.NetConn()
	}
	sys, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	got := congestionOf(t, server)
	t.Logf("system default %q, accepted connection %q", strings.TrimSpace(string(sys)), got)
	if got != "bbr" {
		t.Fatalf("accepted connection uses %q, want bbr", got)
	}
}
