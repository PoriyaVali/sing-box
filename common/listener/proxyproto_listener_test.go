package listener

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"
)

// captureHandler records what the listener hands the protocol above it.
type captureHandler struct {
	sources chan string
	firstB  chan []byte
}

func (h *captureHandler) NewConnectionEx(ctx context.Context, conn net.Conn, m adapter.InboundContext, onClose N.CloseHandlerFunc) {
	h.sources <- m.Source.String()
	buf := make([]byte, 32)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	h.firstB <- buf[:n]
	conn.Close()
}

func newTestListener(t *testing.T, h *captureHandler) *Listener {
	t.Helper()
	return New(Options{
		Context: context.Background(),
		Logger:  log.NewNOPFactory().NewLogger("test"),
		Network: []string{N.NetworkTCP},
		Listen: option.ListenOptions{
			Listen:        (*badoption.Addr)(&[]netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}[0]),
			ProxyProtocol: true,
		},
		ConnectionHandler: h,
	})
}

func v2HeaderFor(src netip.Addr, srcPort, dstPort uint16) []byte {
	b := make([]byte, 0, 28)
	b = append(b, proxyV2Signature[:]...)
	b = append(b, 0x21, 0x11, 0x00, 12)
	a4 := src.As4()
	b = append(b, a4[:]...)
	b = append(b, 127, 0, 0, 1)
	b = binary.BigEndian.AppendUint16(b, srcPort)
	b = binary.BigEndian.AppendUint16(b, dstPort)
	return b
}

// The end-to-end path the production node actually takes: a relay dials over
// loopback, writes the header, then the client's bytes follow.
func TestListenerRecoversSourceThroughLoopback(t *testing.T) {
	h := &captureHandler{sources: make(chan string, 4), firstB: make(chan []byte, 4)}
	l := newTestListener(t, h)
	if err := l.Start(); err != nil {
		t.Fatalf("listener refused to start with ProxyProtocol set: %v", err)
	}
	defer l.Close()

	addr := l.tcpListener.Addr().(*net.TCPAddr)
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := netip.MustParseAddr("5.127.9.9")
	_, _ = c.Write(append(v2HeaderFor(client, 4321, uint16(addr.Port)), []byte("CLIENTHELLO")...))

	select {
	case got := <-h.sources:
		if got != "5.127.9.9:4321" {
			t.Errorf("source = %s, want 5.127.9.9:4321", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran - the accept loop is stuck")
	}
	select {
	case b := <-h.firstB:
		if string(b) != "CLIENTHELLO" {
			t.Errorf("first bytes = %q, want %q", b, "CLIENTHELLO")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no payload reached the handler")
	}
}

// 🔴 The failure this whole feature can cause in production, and the one that
// cannot be seen from the node's own log: a connection that opens and sends
// NOTHING. Sniffing the header in the accept loop blocks on it, and while it
// blocks the listener accepts nobody else - one idle probe takes the whole
// inbound down. The relay's watchdog does exactly this, and so does any port
// scanner.
func TestSilentConnectionDoesNotStallTheAcceptLoop(t *testing.T) {
	h := &captureHandler{sources: make(chan string, 4), firstB: make(chan []byte, 4)}
	l := newTestListener(t, h)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.tcpListener.Addr().(*net.TCPAddr)

	// A connection that says nothing, and is never closed.
	silent, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	time.Sleep(150 * time.Millisecond)

	// A real user arriving behind it must still be served.
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client := netip.MustParseAddr("5.127.9.9")
	_, _ = c.Write(append(v2HeaderFor(client, 4321, uint16(addr.Port)), []byte("CLIENTHELLO")...))

	select {
	case got := <-h.sources:
		if got != "5.127.9.9:4321" {
			t.Errorf("source = %s, want the real client", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a silent connection stalled the accept loop - no later client can be served")
	}
}
