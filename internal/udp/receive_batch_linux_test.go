package udp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReceiveBatchNativeQueue(t *testing.T) {
	packet := newUDPConnLocalhost(t)
	require.NoError(t, packet.SetReadBuffer(1<<20))
	conn, err := Wrap(packet, 1472, 45)
	require.NoError(t, err)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { peer.Close() })
	for i := range 52 {
		_, err = peer.WriteTo(fmt.Appendf(nil, "datagram %d", i), packet.LocalAddr())
		require.NoError(t, err)
	}

	for i := range 52 {
		p, err := conn.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("datagram %d", i), string(p.Data))
		p.Buffer.Release()
		if i == 0 {
			require.Len(t, conn.(*oobConn).messages, 45, "one native read must consume the queued full batch")
		}
	}
}
