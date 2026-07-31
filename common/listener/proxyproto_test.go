package listener

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeConn lets a test choose the peer address, which is the input the whole
// security rule turns on.
type fakeConn struct {
	net.Conn
	remote net.Addr
	buf    *bytes.Buffer
}

func (c *fakeConn) Read(b []byte) (int, error)       { return c.buf.Read(b) }
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443} }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.remote }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func mkConn(peer string, payload []byte) *fakeConn {
	ap := netip.MustParseAddrPort(peer)
	return &fakeConn{
		remote: net.TCPAddrFromAddrPort(ap),
		buf:    bytes.NewBuffer(payload),
	}
}

func v2Header(family byte, src netip.Addr, srcPort uint16, cmd byte) []byte {
	var body []byte
	switch family {
	case proxyFamilyINET:
		b := make([]byte, 12)
		a4 := src.As4()
		copy(b[0:4], a4[:])
		copy(b[4:8], []byte{10, 0, 0, 1})
		binary.BigEndian.PutUint16(b[8:10], srcPort)
		binary.BigEndian.PutUint16(b[10:12], 8443)
		body = b
	case proxyFamilyINET6:
		b := make([]byte, 36)
		a16 := src.As16()
		copy(b[0:16], a16[:])
		binary.BigEndian.PutUint16(b[32:34], srcPort)
		binary.BigEndian.PutUint16(b[34:36], 8443)
		body = b
	}
	h := make([]byte, proxyV2HeaderLen)
	copy(h[:12], proxyV2Signature[:])
	h[12] = 0x20 | cmd
	h[13] = family<<4 | 0x1
	binary.BigEndian.PutUint16(h[14:16], uint16(len(body)))
	return append(h, body...)
}

// 🔴 The one that matters. A header from a NON-loopback peer must be ignored
// entirely - believing it would let anyone on the internet claim any source
// address and walk past a ban or a device limit.
func TestHeaderFromInternetPeerIsNeverTrusted(t *testing.T) {
	client := netip.MustParseAddr("5.127.1.1")
	payload := append(v2Header(proxyFamilyINET, client, 1234, proxyCmdProxy), []byte("DATA")...)
	c := mkConn("203.0.113.7:51000", payload)

	out := readProxyHeader(c)
	if got := out.RemoteAddr().String(); got != "203.0.113.7:51000" {
		t.Fatalf("remote = %s, want the real peer - a forged header was believed", got)
	}
	// And nothing may be consumed, or we would corrupt a normal connection.
	rest := make([]byte, len(payload))
	n, _ := out.Read(rest)
	if !bytes.Equal(rest[:n], payload[:n]) {
		t.Error("bytes were consumed from an untrusted connection")
	}
}

func TestLoopbackHeaderRecoversTheClientAddress(t *testing.T) {
	client := netip.MustParseAddr("5.127.1.1")
	payload := append(v2Header(proxyFamilyINET, client, 1234, proxyCmdProxy), []byte("DATA")...)
	c := mkConn("127.0.0.1:40000", payload)

	out := readProxyHeader(c)
	if got := out.RemoteAddr().String(); got != "5.127.1.1:1234" {
		t.Fatalf("remote = %s, want 5.127.1.1:1234", got)
	}
	// The header must not reach the protocol above it.
	rest := make([]byte, 16)
	n, _ := out.Read(rest)
	if string(rest[:n]) != "DATA" {
		t.Errorf("payload = %q, want %q - the header leaked into the stream", rest[:n], "DATA")
	}
}

func TestLoopbackIPv6Header(t *testing.T) {
	client := netip.MustParseAddr("2001:db8::1")
	payload := append(v2Header(proxyFamilyINET6, client, 9999, proxyCmdProxy), []byte("X")...)
	out := readProxyHeader(mkConn("127.0.0.1:40000", payload))
	if got := out.RemoteAddr().String(); got != "[2001:db8::1]:9999" {
		t.Fatalf("remote = %s, want [2001:db8::1]:9999", got)
	}
}

// A local health check or the decoy fallback sends no header. Passing it through
// unchanged is deliberate: failing closed would trade a counting gap for an
// outage on the same port.
func TestLoopbackWithoutHeaderPassesThrough(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	c := mkConn("127.0.0.1:40000", payload)

	out := readProxyHeader(c)
	if got := out.RemoteAddr().String(); got != "127.0.0.1:40000" {
		t.Errorf("remote = %s, want the loopback peer", got)
	}
	rest := make([]byte, len(payload))
	n, _ := out.Read(rest)
	if string(rest[:n]) != string(payload) {
		t.Errorf("payload = %q, want it untouched", rest[:n])
	}
}

// LOCAL means "my own health check" - consume the header, keep the peer.
func TestLocalCommandKeepsThePeerButEatsTheHeader(t *testing.T) {
	client := netip.MustParseAddr("5.127.1.1")
	payload := append(v2Header(proxyFamilyINET, client, 1234, proxyCmdLocal), []byte("DATA")...)
	out := readProxyHeader(mkConn("127.0.0.1:40000", payload))
	if got := out.RemoteAddr().String(); got != "127.0.0.1:40000" {
		t.Errorf("remote = %s, want the loopback peer for a LOCAL command", got)
	}
	rest := make([]byte, 8)
	n, _ := out.Read(rest)
	if string(rest[:n]) != "DATA" {
		t.Errorf("payload = %q, want %q", rest[:n], "DATA")
	}
}

// A truncated header must not be half-consumed, or the stream above is ruined.
func TestTruncatedHeaderIsLeftAlone(t *testing.T) {
	full := v2Header(proxyFamilyINET, netip.MustParseAddr("5.127.1.1"), 1234, proxyCmdProxy)
	payload := full[:len(full)-4]
	c := mkConn("127.0.0.1:40000", payload)

	out := readProxyHeader(c)
	if got := out.RemoteAddr().String(); got != "127.0.0.1:40000" {
		t.Errorf("remote = %s, want the peer", got)
	}
	rest := make([]byte, len(payload))
	n, _ := out.Read(rest)
	if !bytes.Equal(rest[:n], payload) {
		t.Error("a truncated header was partially consumed")
	}
}

// 🔴 Regression: the wrapper must not expose the raw connection.
//
// Declaring Upstream() let sing's copy paths read the underlying conn directly,
// bypassing the buffer that necessarily holds the bytes read ahead while
// sniffing the header - the start of the client's ClientHello. Those bytes were
// dropped and the handshake failed, but ONLY through the relay: a direct
// connection is never wrapped, so it kept working, which is what made the
// breakage look like a tunnel problem rather than a parser problem.
func TestWrapperDoesNotExposeTheRawConn(t *testing.T) {
	client := netip.MustParseAddr("5.127.1.1")
	// A payload big enough that sniffing reads ahead into it.
	body := bytes.Repeat([]byte("HANDSHAKE"), 40)
	payload := append(v2Header(proxyFamilyINET, client, 1234, proxyCmdProxy), body...)
	out := readProxyHeader(mkConn("127.0.0.1:40000", payload))

	if _, bad := out.(interface{ Upstream() any }); bad {
		t.Fatal("the wrapper exposes Upstream(); sing will bypass the buffer and drop the read-ahead bytes")
	}

	// Everything after the header must survive, byte for byte.
	got := make([]byte, 0, len(body))
	buf := make([]byte, 7) // small reads, so the buffer is genuinely exercised
	for len(got) < len(body) {
		n, err := out.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			break
		}
	}
	if !bytes.Equal(got, body) {
		t.Errorf("payload after the header was corrupted: got %d of %d bytes", len(got), len(body))
	}
}
