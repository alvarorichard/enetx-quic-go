//go:build darwin

package udp

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

func TestIPv4SourceAddressDoesNotSetDarwinInterface(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.2")
	info := PacketInfo{Addr: ip, IfIndex: 7}
	messages, err := unix.ParseSocketControlMessage(info.OOB())
	require.NoError(t, err)
	require.Len(t, messages, 1)
	require.EqualValues(t, unix.IPPROTO_IP, messages[0].Header.Level)
	require.EqualValues(t, unix.IP_PKTINFO, messages[0].Header.Type)
	require.Len(t, messages[0].Data, 12)
	require.Zero(t, binary.NativeEndian.Uint32(messages[0].Data[:4]))
	require.Equal(t, ip.AsSlice(), messages[0].Data[4:8])
}
