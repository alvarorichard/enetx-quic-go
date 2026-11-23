//go:build darwin || linux || freebsd

package udp

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type configuredBatchConn struct {
	*mockBatchConn
	capacity int
	width    int
	last     int
}

func (c *configuredBatchConn) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	require.Len(c.t, messages, c.capacity)
	count := c.capacity
	if c.callCounter%2 != 0 {
		count = 1
	}

	for i := range count {
		require.Len(c.t, messages[i].Buffers[0], c.width)
		messages[i].N = 4
		binary.BigEndian.PutUint32(messages[i].Buffers[0], uint32(c.last+i))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&messages[i].OOB[0]))
		header.Level, header.Type = unix.IPPROTO_IP, msgTypeIPTOS
		header.SetLen(unix.CmsgLen(1))
		messages[i].OOB[unix.CmsgLen(0)] = protocol.ECNCE.ToHeaderBits()
		messages[i].NN = unix.CmsgSpace(1)
	}

	c.last += count
	c.callCounter++
	return count, nil
}

func TestConfiguredBatchCapacityAndBufferOwnership(t *testing.T) {
	for _, size := range []int{0, 1, 8, 45, 255} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			capacity := size
			if capacity == 0 || batchSize == 1 {
				capacity = batchSize
			}

			peer := &configuredBatchConn{
				mockBatchConn: &mockBatchConn{UDPConn: newUDPConnLocalhost(t), t: t},
				capacity:      capacity, width: 1472,
			}
			conn, err := Wrap(peer, peer.width, size)
			require.NoError(t, err)
			var held []Packet
			for i := range 2*capacity + 1 {
				packet, err := conn.ReadPacket()
				require.NoError(t, err)
				require.EqualValues(t, i, binary.BigEndian.Uint32(packet.Data))
				require.Equal(t, protocol.ECNCE, packet.ECN)
				held = append(held, packet)
			}

			require.Equal(t, 3, peer.callCounter, "full/partial/full batches")
			for i, packet := range held {
				require.EqualValues(t, i, binary.BigEndian.Uint32(packet.Data), "later reads must not overwrite held packets")
				packet.Buffer.Release()
			}
		})
	}
}
