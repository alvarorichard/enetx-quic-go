package udp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReceiveBatchValidationAndBasicSocket(t *testing.T) {
	for _, size := range []int{-1, 256} {
		conn, err := Wrap(nil, 0, size)
		require.Nil(t, conn)
		require.ErrorContains(t, err, "QUIC receive batch size")
	}

	for _, size := range []int{0, 1, 8, 45, 255} {
		require.NoError(t, ValidateReceiveBatchSize(size))
	}

	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { packet.Close() })
	conn, err := Wrap(struct{ net.PacketConn }{packet}, 1472, 45)
	require.NoError(t, err)
	conn.(*basicConn).setReadBatchSize(45)
	wrapped, err := Wrap(packet, 1472)
	require.NoError(t, err)
	reused, err := Wrap(wrapped.(net.PacketConn), 1472, 45)
	require.NoError(t, err)
	require.Same(t, wrapped, reused)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close() })
	_, err = peer.WriteTo([]byte("basic read"), packet.LocalAddr())
	require.NoError(t, err)
	result, err := conn.ReadPacket()
	require.NoError(t, err)
	defer result.Buffer.Release()
	require.Equal(t, "basic read", string(result.Data))
}
