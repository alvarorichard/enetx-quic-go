package quic_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestTransportRejectsInvalidReceiveBatchBeforeTakingSocket(t *testing.T) {
	for _, size := range []int{-1, 256} {
		packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		transport := &quic.Transport{Conn: packet, ReceiveBatchSize: size}
		conn, err := transport.Dial(t.Context(), packet.LocalAddr(), &tls.Config{ServerName: "localhost"}, nil)
		require.Nil(t, conn)
		require.ErrorContains(t, err, "QUIC receive batch size")
		require.NoError(t, packet.Close(), "invalid configuration retains caller socket ownership")
	}
}
