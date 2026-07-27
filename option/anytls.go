package option

import "github.com/sagernet/sing/common/json/badoption"

type AnyTLSInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users         []AnyTLSUser               `json:"users,omitempty"`
	PaddingScheme badoption.Listable[string] `json:"padding_scheme,omitempty"`
	// Fallback is where a connection goes when it completed the TLS handshake
	// but is not one of our users — which is exactly what an active prober is.
	// Without it the server hangs up the moment the password does not match,
	// and a listener that answers TLS and then instantly closes on any real
	// request does not behave like anything on the public internet. Pointing
	// this at a local web server makes the port answer like the site its
	// certificate is for. Same shape as the trojan inbound's option.
	Fallback *ServerOptions `json:"fallback,omitempty"`
}

type AnyTLSUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type AnyTLSOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password                 string             `json:"password,omitempty"`
	IdleSessionCheckInterval badoption.Duration `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                `json:"min_idle_session,omitempty"`
}
