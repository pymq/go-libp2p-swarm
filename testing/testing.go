package testing

import (
	"context"
	"github.com/libp2p/go-libp2p-core/connmgr"
	"github.com/libp2p/go-libp2p-core/control"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	"testing"

	"github.com/libp2p/go-libp2p-core/metrics"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/libp2p/go-libp2p-testing/net"
	"github.com/libp2p/go-tcp-transport"

	goprocess "github.com/jbenet/goprocess"
	csms "github.com/libp2p/go-conn-security-multistream"
	pstoremem "github.com/libp2p/go-libp2p-peerstore/pstoremem"
	secio "github.com/libp2p/go-libp2p-secio"
	tptu "github.com/libp2p/go-libp2p-transport-upgrader"
	yamux "github.com/libp2p/go-libp2p-yamux"
	msmux "github.com/libp2p/go-stream-muxer-multistream"

	swarm "github.com/libp2p/go-libp2p-swarm"
)

type config struct {
	disableReuseport bool
	dialOnly         bool
	connectionGater  connmgr.ConnectionGater
}

// Option is an option that can be passed when constructing a test swarm.
type Option func(*testing.T, *config)

// OptDisableReuseport disables reuseport in this test swarm.
var OptDisableReuseport Option = func(_ *testing.T, c *config) {
	c.disableReuseport = true
}

// OptDialOnly prevents the test swarm from listening.
var OptDialOnly Option = func(_ *testing.T, c *config) {
	c.dialOnly = true
}

// OptConnGater configures the given connection gater on the test
func OptConnGater(cg connmgr.ConnectionGater) Option {
	return func(_ *testing.T, c *config) {
		c.connectionGater = cg
	}
}

// GenUpgrader creates a new connection upgrader for use with this swarm.
func GenUpgrader(n *swarm.Swarm) *tptu.Upgrader {
	id := n.LocalPeer()
	pk := n.Peerstore().PrivKey(id)
	secMuxer := new(csms.SSMuxer)
	secMuxer.AddTransport(secio.ID, &secio.Transport{
		LocalID:    id,
		PrivateKey: pk,
	})

	stMuxer := msmux.NewBlankTransport()
	stMuxer.AddTransport("/yamux/1.0.0", yamux.DefaultTransport)

	return &tptu.Upgrader{
		Secure:    secMuxer,
		Muxer:     stMuxer,
		ConnGater: n.ConnGater,
	}

}

// GenSwarm generates a new test swarm.
func GenSwarm(t *testing.T, ctx context.Context, opts ...Option) *swarm.Swarm {
	var cfg config
	for _, o := range opts {
		o(t, &cfg)
	}

	p := tnet.RandPeerNetParamsOrFatal(t)

	ps := pstoremem.NewPeerstore()
	ps.AddPubKey(p.ID, p.PubKey)
	ps.AddPrivKey(p.ID, p.PrivKey)
	s := swarm.NewSwarm(ctx, p.ID, ps, metrics.NewBandwidthCounter())
	s.ConnGater = cfg.connectionGater
	s.Process().AddChild(goprocess.WithTeardown(ps.Close))

	tcpTransport := tcp.NewTCPTransport(GenUpgrader(s))
	tcpTransport.DisableReuseport = cfg.disableReuseport

	if err := s.AddTransport(tcpTransport); err != nil {
		t.Fatal(err)
	}

	if !cfg.dialOnly {
		if err := s.Listen(p.Addr); err != nil {
			t.Fatal(err)
		}

		s.Peerstore().AddAddrs(p.ID, s.ListenAddresses(), peerstore.PermanentAddrTTL)
	}

	return s
}

// DivulgeAddresses adds swarm a's addresses to swarm b's peerstore.
func DivulgeAddresses(a, b network.Network) {
	id := a.LocalPeer()
	addrs := a.Peerstore().Addrs(id)
	b.Peerstore().AddAddrs(id, addrs, peerstore.PermanentAddrTTL)
}

// MockConnectionGater is a mock connection gater to be used by the tests.
type MockConnectionGater struct {
	Dial     func(addr ma.Multiaddr) bool
	PeerDial func(p peer.ID) bool
	Accept   func(c network.ConnMultiaddrs) bool
	Secured  func(network.Direction, peer.ID, network.ConnMultiaddrs) bool
	Upgraded func(tc transport.CapableConn) (bool, control.DisconnectReason)
}

func DefaultMockConnectionGater() *MockConnectionGater {
	m := &MockConnectionGater{}
	m.Dial = func(addr ma.Multiaddr) bool {
		return true
	}

	m.PeerDial = func(p peer.ID) bool {
		return true
	}

	m.Accept = func(c network.ConnMultiaddrs) bool {
		return true
	}

	m.Secured = func(network.Direction, peer.ID, network.ConnMultiaddrs) bool {
		return true
	}

	m.Upgraded = func(tc transport.CapableConn) (bool, control.DisconnectReason) {
		return true, 0
	}

	return m
}

func (m *MockConnectionGater) InterceptDial(addr ma.Multiaddr) (allow bool) {
	return m.Dial(addr)
}

// InterceptPeerDial tests whether we're permitted to dial the specified peer.
// This is to be called by the network/swarm when dialling.
func (m *MockConnectionGater) InterceptPeerDial(p peer.ID) (allow bool) {
	return m.PeerDial(p)
}

// InterceptAccept tests whether an incipient inbound connection is allowed.
// network.ConnMultiaddrs is what we pass to the upgrader.
// This is intended to be called by the upgrader, or by the transport
// directly (e.g. QUIC, Bluetooth), straight after it's accepted a connection
// from its socket.
func (m *MockConnectionGater) InterceptAccept(c network.ConnMultiaddrs) (allow bool) {
	return m.Accept(c)
}

// InterceptSecured tests whether a given connection, now authenticated,
// is allowed.
// This is intended to be called by the upgrader, after it has negotiated crypto,
// and before it negotiates the muxer, or by the directly by the transport,
// at the exact same checkpoint.
func (m *MockConnectionGater) InterceptSecured(d network.Direction, p peer.ID, c network.ConnMultiaddrs) (allow bool) {
	return m.Secured(d, p, c)
}

// InterceptUpgraded tests whether a fully capable connection is allowed.
// At this point, we have a multiplexer, so the middleware can
// return a DisconnectReason.
// and the swarm would use the control stream to convey it to the peer.
func (m *MockConnectionGater) InterceptUpgraded(tc transport.CapableConn) (allow bool, reason control.DisconnectReason) {
	return m.Upgraded(tc)
}
