package quic_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestDialRejectsInvalidAndInconsistentReceiveLimits(t *testing.T) {
	for _, size := range []int{1199, 1200} {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		defer packet.Close()
		transport := &quic.Transport{Conn: packet, ReceivePacketSize: size}
		defer transport.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		conn, err := transport.Dial(ctx, packet.LocalAddr(), &tls.Config{
			ServerName: "localhost", NextProtos: []string{"receive-limit-test"},
		}, &quic.Config{ClientHandshake: &quic.ClientHandshake{MaxUDPPayloadSize: 1472}})
		cancel()
		require.Nil(t, conn)
		if size == 1199 {
			require.ErrorContains(t, err, "QUIC receive packet size")
		} else {
			require.ErrorContains(t, err, "exceeds transport receive size")
		}
	}
}
