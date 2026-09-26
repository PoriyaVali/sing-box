package anytls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func selfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "node.test"},
		DNSNames:     []string{"node.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

func heldSessions(h *Inbound) int {
	n := 0
	h.userconns.Range(func(_, _ any) bool { n++; return true })
	return n
}

// A session that authenticates and then ends without ever opening a stream -
// a device that drops right after the handshake - must leave nothing behind.
// The session-level onClose is only ever handed to STREAMS, so such a session
// never called it, and its userconns entry (holding the TLS connection and its
// buffers) stayed until the process restarted.
func TestInbound_EmptySessionIsForgotten(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	logger := log.NewNOPFactory().NewLogger("anytls")
	in, err := NewInbound(context.Background(), nil, logger, "anytls-in", option.AnyTLSInboundOptions{
		Users: []option.AnyTLSUser{{Name: "u1", Password: "u1"}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled:     true,
			Certificate: []string{certPEM},
			Key:         []string{keyPEM},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*Inbound)
	auth := sha256.Sum256([]byte("u1"))

	const sessions = 50
	var wg sync.WaitGroup
	for i := 0; i < sessions; i++ {
		serverSide, clientSide := net.Pipe()
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.NewConnectionEx(context.Background(), serverSide,
				adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.7:40000")}, nil)
		}()
		client := stdtls.Client(clientSide, &stdtls.Config{InsecureSkipVerify: true, ServerName: "node.test"})
		if err := client.Handshake(); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		// Password hash and a zero padding length: an authenticated session
		// that never sends a single frame.
		if _, err := client.Write(append(auth[:], 0, 0)); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		client.Close()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("sessions did not end")
	}
	if n := heldSessions(h); n != 0 {
		t.Fatalf("%d of %d ended sessions are still held in userconns", n, sessions)
	}
}
