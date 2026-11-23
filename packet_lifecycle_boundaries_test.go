package quic

import (
	"testing"

	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestDroppedInitialRecoveryCannotRetainOrResurrectTranscriptBytes(t *testing.T) {
	conn := newClientTestConnection(t, gomock.NewController(t), &Config{
		ClientHandshake: &ClientHandshake{InitialCryptoRecovery: true},
	}, false)
	recovery := conn.conn.cryptoStreamManager.initialStream.recovery
	hello, err := getClientHello("retired.example")
	require.NoError(t, err)
	_, err = conn.conn.cryptoStreamManager.initialStream.Write(hello)
	require.NoError(t, err)
	conn.conn.retransmissionQueue.addInitial(&wire.CryptoFrame{Data: hello})
	conn.conn.retransmissionQueue.DropPackets(protocol.EncryptionInitial)
	require.True(t, recovery.closed)
	require.Nil(t, recovery.data)
	recovery.OnLost(&wire.CryptoFrame{Data: []byte("late loss")})
	require.Nil(t, recovery.pending)
	conn.conn.cryptoStreamManager.Drop(protocol.EncryptionInitial)
	ordered, err := (&packetPacker{cryptoStreamManager: conn.conn.cryptoStreamManager}).prepareInitialCryptoPacket(
		protocol.EncryptionInitial, 1200, 1100)
	require.NoError(t, err)
	require.False(t, ordered, "discarded Initial keys must not recreate an Initial layout")
}

func TestPacketBudgetWithoutPolicyOrExplicitLengthPreservesNativeContract(t *testing.T) {
	// Final STREAM frames omit the length field (RFC 9000 section 19.8).
	// No temporary varint reservation is needed in that representation.
	frame := &wire.StreamFrame{StreamID: 64, Offset: 16384}
	for _, budget := range []protocol.ByteCount{0, 63, 64, 1200} {
		require.Equal(t, budget, streamPacketSizeWithLength(budget, frame, protocol.Version1))
	}

	// A native packer has no coalesced-budget policy. This optional hook must
	// remain a no-op, including after application packet-space transitions.
	(&packetPacker{}).recordCoalescedPacketSize(nil, 16, 1200, protocol.Version1)
}
