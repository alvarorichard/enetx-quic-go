package udp

import (
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestReceivePacketBufferPools(t *testing.T) {
	buffer := receivePacketBuffer(0)
	require.Len(t, buffer.Data, protocol.MaxPacketBufferSize)
	buffer.Release()
	// Omitting the UDP limit advertises the protocol's 65527-byte default.
	// Both pooled receive paths must retain their requested length on reuse.
	for range 2 {
		for _, size := range []int{1472, protocol.MaxLargePacketBufferSize, MaxUDPReceivePacketSize} {
			buffer := receivePacketBuffer(size)
			require.Len(t, buffer.Data, size)
			buffer.Release()
		}
	}
	require.Error(t, ValidateReceivePacketSize(1199))
	require.Error(t, ValidateReceivePacketSize(MaxUDPReceivePacketSize+1))
}
