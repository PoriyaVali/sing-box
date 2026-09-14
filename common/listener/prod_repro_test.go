package listener

import (
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"
)

// The exact 28 bytes tcpdump captured arriving at the live inbound, delivered
// the way production delivers them: alone, with the client's data only later.
func TestExactProductionBytes(t *testing.T) {
	raw, err := hex.DecodeString("0d0a0d0a000d0a515549540a" + "2111" + "000c" +
		"2ef661ad" + "7f000001" + "94ee" + "20fb")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 28 {
		t.Fatalf("fixture is %d bytes, expected 28", len(raw))
	}

	h := &captureHandler{sources: make(chan string, 4), firstB: make(chan []byte, 4)}
	l := newTestListener(t, h)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	addr := l.tcpListener.Addr().(*net.TCPAddr)

	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// header alone, exactly as the egress writes it
	if _, err := c.Write(raw); err != nil {
		t.Fatal(err)
	}
	// then the client's first bytes arrive separately, after a pause
	time.Sleep(200 * time.Millisecond)
	_, _ = c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05})

	want := netip.MustParseAddr("46.246.97.173")
	select {
	case got := <-h.sources:
		t.Logf("source seen by the inbound: %s", got)
		if got != want.String()+":38126" {
			t.Errorf("source = %s, want %s:38126", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler never ran")
	}
	select {
	case b := <-h.firstB:
		t.Logf("first bytes handed up: % x", b)
		if len(b) > 0 && b[0] != 0x16 {
			t.Errorf("the header leaked into the stream: % x", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no payload reached the handler")
	}
}
