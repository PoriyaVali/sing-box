package anytls

import (
	"context"
	"crypto/sha256"
	stdtls "crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const physicalUser = "panel-user"
const physicalPassword = "separate authentication password"

func physicalInbound(t *testing.T) *Inbound {
	t.Helper()
	certPEM, keyPEM := selfSignedPEM(t)
	in, err := NewInbound(context.Background(), nil, log.NewNOPFactory().NewLogger("anytls"), "anytls-in", option.AnyTLSInboundOptions{
		Users: []option.AnyTLSUser{{Name: physicalUser, Password: physicalPassword}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, Certificate: []string{certPEM}, Key: []string{keyPEM},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h := in.(*Inbound)
	if _, ok := any(h.service).(interface {
		SetAuthenticatedSessionHandler(func(context.Context, net.Conn) (func(), error))
	}); !ok {
		_ = h.Close()
		t.Skip("physical-session tests require the V2bX sing-anytls callback")
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func physicalClient(t *testing.T, h *Inbound) *stdtls.Conn {
	t.Helper()
	server, rawClient := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.NewConnectionEx(context.Background(), server,
			adapter.InboundContext{Source: M.ParseSocksaddr("198.51.100.7:40000")}, nil)
	}()
	t.Cleanup(func() {
		_ = rawClient.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("physical session did not stop")
		}
	})
	client := stdtls.Client(rawClient, &stdtls.Config{InsecureSkipVerify: true, ServerName: "node.test"})
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	return client
}

func writePhysicalAuth(t *testing.T, client *stdtls.Conn) {
	writePhysicalPassword(t, client, physicalPassword)
}

func writePhysicalPassword(t *testing.T, client *stdtls.Conn, password string) {
	t.Helper()
	hash := sha256.Sum256([]byte(password))
	if _, err := client.Write(append(hash[:], 0, 0)); err != nil {
		t.Fatal(err)
	}
}

func waitPhysicalSessions(t *testing.T, h *Inbound, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if heldSessions(h) == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("held physical sessions = %d, want %d", heldSessions(h), want)
}

func readPhysicalClose(client *stdtls.Conn) error {
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := client.Read(make([]byte, 1))
	if err == nil {
		return errors.New("unexpected application data on idle session")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		return errors.New("physical session remains open")
	}
	return nil
}

func TestDelUsersClosesAuthenticatedIdlePhysicalSession(t *testing.T) {
	h := physicalInbound(t)
	client := physicalClient(t, h)
	writePhysicalAuth(t, client)
	waitPhysicalSessions(t, h, 1)
	closed := make(chan error, 1)
	go func() { closed <- readPhysicalClose(client) }()
	if err := h.DelUsers([]string{physicalUser}); err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	waitPhysicalSessions(t, h, 0)
}

func TestCloseClosesPhysicalSessionBeforeAnyAuthentication(t *testing.T) {
	h := physicalInbound(t)
	client := physicalClient(t, h)
	closed := make(chan error, 1)
	go func() { closed <- readPhysicalClose(client) }()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestLatePhysicalAuthenticationRejectsReaddedGeneration(t *testing.T) {
	h := physicalInbound(t)
	// Use equal name/password here so the baseline's separate password-reset
	// bug cannot make a stale generation appear to be correctly rejected.
	user := option.AnyTLSUser{Name: physicalUser, Password: physicalUser}
	if err := h.AddUsers([]option.AnyTLSUser{user}); err != nil {
		t.Fatal(err)
	}
	client := physicalClient(t, h)
	if err := h.DelUsers([]string{physicalUser}); err != nil {
		t.Fatal(err)
	}
	if err := h.AddUsers([]option.AnyTLSUser{user}); err != nil {
		t.Fatal(err)
	}
	writePhysicalPassword(t, client, physicalUser)
	if err := readPhysicalClose(client); err != nil {
		t.Fatal(err)
	}
	waitPhysicalSessions(t, h, 0)
}
