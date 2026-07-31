package listener

import (
	"bufio"
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

// How long a peer gets to produce a header before we stop waiting for one.
const proxyHeaderTimeout = 5 * time.Second

// HAProxy PROXY protocol v2, enough of it to recover the real client address of
// a connection that reached us through a local relay.
//
// Upstream sing-box removed PROXY-protocol support in 1.6.0 and ListenTCP still
// refuses the option outright. That is fine for a listener facing the internet -
// a header is a claim, and an unauthenticated claim about who you are is worth
// nothing. It is not fine here: our Iran-relay front terminates the user's TCP
// connection and dials this node over loopback, so every tunnelled user arrives
// as 127.0.0.1. They are then invisible to device counting and to the online
// list, because the node genuinely cannot tell them apart.
//
// 🔴 The header is trusted ONLY when the peer is loopback. That is the whole
// security argument, and it is not a detail:
//
//   - the relay's egress dials this inbound on 127.0.0.1, so a genuine tunnelled
//     connection always has a loopback peer;
//   - anyone reaching the public port from the internet has a non-loopback peer,
//     so their header is never read - if it were, they could name any source
//     address they liked and walk straight past a ban or a device limit, which
//     would be strictly worse than the problem being solved.
//
// A loopback peer that sends no header is passed through unchanged rather than
// rejected: the same port is also reached locally by health checks and by the
// decoy fallback, and failing those closed would trade a counting gap for an
// outage.

var proxyV2Signature = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

const (
	proxyV2HeaderLen = 16 // signature + version/command + family + length
	proxyCmdLocal    = 0x0
	proxyCmdProxy    = 0x1
	proxyFamilyINET  = 0x1
	proxyFamilyINET6 = 0x2
)

// proxyProtoConn reports the address named in the PROXY header as its remote
// address, so everything downstream - routing, the traffic hooks, device
// counting - sees the real client without knowing a relay exists.
//
// Reads go through the buffered reader used to sniff the header, because
// sniffing may have pulled in bytes that belong to the protocol above.
type proxyProtoConn struct {
	net.Conn
	reader *bufio.Reader
	source net.Addr
}

func (c *proxyProtoConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

func (c *proxyProtoConn) RemoteAddr() net.Addr {
	if c.source != nil {
		return c.source
	}
	return c.Conn.RemoteAddr()
}

// 🔴 Deliberately NO Upstream() method.
//
// Declaring one is the obvious optimisation and it silently breaks the
// connection: sing's copy paths treat an upstream as "you may read the
// underlying conn directly", so they bypass the buffered reader above. Sniffing
// the header necessarily reads ahead - bufio pulls in whatever arrived with it,
// which is the start of the client's TLS ClientHello - and those bytes live only
// in that buffer. Handing out the raw conn throws them away, so the handshake
// receives a stream missing its first bytes and fails, while a direct connection
// (never wrapped, because its peer is not loopback) keeps working. That
// asymmetry is exactly how it presented: fine directly, broken through the relay.
//
// Without the method sing wraps this like any other net.Conn and every read goes
// through the buffer, which is what correctness requires here.

// peerIsLoopback reports whether the connection's actual peer is on this
// machine - the only case in which a PROXY header may be believed.
func peerIsLoopback(conn net.Conn) bool {
	addrPort, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	return addrPort.Addr().Unmap().IsLoopback()
}

// readProxyHeader returns the connection to use. When the peer is loopback and a
// well-formed v2 header is present it is consumed and the real client address is
// attached; otherwise the connection is returned with nothing consumed.
func readProxyHeader(conn net.Conn) net.Conn {
	if !peerIsLoopback(conn) {
		return conn
	}
	// Sized for the largest header we accept (16 + IPv6 address block), so a
	// well-formed header never spills into a second fill.
	reader := bufio.NewReaderSize(conn, proxyV2HeaderLen+36)
	wrapped := &proxyProtoConn{Conn: conn, reader: reader}

	// A relay writes the header the instant it dials, so waiting seconds for one
	// only ever means it is not coming. Without this bound a peer that connects
	// and stays silent pins a goroutine and its socket for as long as it likes,
	// which is a free way to exhaust the node. The deadline is cleared again
	// below so the protocol above gets a connection with no surprise timeout.
	_ = conn.SetReadDeadline(time.Now().Add(proxyHeaderTimeout))
	defer conn.SetReadDeadline(time.Time{})

	head, err := reader.Peek(proxyV2HeaderLen)
	if err != nil || [12]byte(head[:12]) != proxyV2Signature {
		return wrapped // not ours; the bytes stay in the buffer for the caller
	}
	if head[12]>>4 != 2 {
		return wrapped // some other version of the protocol
	}

	bodyLen := int(binary.BigEndian.Uint16(head[14:16]))
	body, err := reader.Peek(proxyV2HeaderLen + bodyLen)
	if err != nil {
		return wrapped // truncated - leave it alone rather than half-consume
	}
	body = body[proxyV2HeaderLen:]

	// LOCAL means "this is my own health check, ignore the addresses". Consume
	// the header so it does not reach the protocol above, but keep the peer.
	if head[12]&0x0F == proxyCmdLocal {
		_, _ = reader.Discard(proxyV2HeaderLen + bodyLen)
		return wrapped
	}
	if head[12]&0x0F != proxyCmdProxy {
		return wrapped
	}

	var src netip.Addr
	var port uint16
	switch head[13] >> 4 {
	case proxyFamilyINET:
		if len(body) < 12 {
			return wrapped
		}
		src = netip.AddrFrom4([4]byte(body[0:4]))
		port = binary.BigEndian.Uint16(body[8:10])
	case proxyFamilyINET6:
		if len(body) < 36 {
			return wrapped
		}
		src = netip.AddrFrom16([16]byte(body[0:16]))
		port = binary.BigEndian.Uint16(body[32:34])
	default:
		// UNSPEC and the AF_UNIX family carry nothing we can use as a client
		// address; consume the header so it does not corrupt the stream.
		_, _ = reader.Discard(proxyV2HeaderLen + bodyLen)
		return wrapped
	}
	if !src.IsValid() {
		return wrapped
	}

	_, _ = reader.Discard(proxyV2HeaderLen + bodyLen)
	wrapped.source = net.TCPAddrFromAddrPort(netip.AddrPortFrom(src.Unmap(), port))
	return wrapped
}
