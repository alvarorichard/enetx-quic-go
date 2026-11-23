package udp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWrapRejectsInvalidReceiveSizeBeforeUsingSocket(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packet.Close() })
	for _, size := range []int{-1, 1199, MaxUDPReceivePacketSize + 1} {
		wrapped, err := Wrap(packet, size)
		require.Error(t, err)
		require.Nil(t, wrapped)
	}

	require.NoError(t, packet.SetReadDeadline(time.Now().Add(time.Second)), "validation must not take socket ownership")
}

func TestBasicConnectionAppliesReceiveSizeAndReadsDatagram(t *testing.T) {
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packet.Close() })
	wrapped := &basicConn{PacketConn: packet}
	wrapped.setReadPacketSize(1472)
	require.NoError(t, wrapped.SetReadDeadline(time.Now().Add(5*time.Second)))
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close() })
	_, err = peer.WriteTo([]byte("receive-size regression"), packet.LocalAddr())
	require.NoError(t, err)
	datagram, err := wrapped.ReadPacket()
	require.NoError(t, err)
	defer datagram.Buffer.Release()
	require.Equal(t, []byte("receive-size regression"), datagram.Data)
	require.Len(t, datagram.Buffer.Data, 1472)
}
