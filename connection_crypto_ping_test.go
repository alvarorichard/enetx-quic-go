package quic

import (
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/monotime"
	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestReceivedCryptoPINGReschedulesOnlyActuallySentUnacknowledgedBytes(t *testing.T) {
	for _, level := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake} {
		t.Run(level.String(), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			conn := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{
				InitialCryptoRecovery: true, InitialCryptoResendOnPeerProbe: true,
				HandshakeCryptoRecovery: true, HandshakeCryptoResendOnPeerProbe: true,
			}}, false)
			data := []byte("client Finished transcript")
			if level == protocol.EncryptionInitial {
				var err error
				data, err = getClientHello("peer-probe.example")
				require.NoError(t, err)
			}

			require.NoError(t, conn.conn.cryptoStreamManager.Write(level, data))
			packer := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			packer.packer.cryptoStreamManager = conn.conn.cryptoStreamManager
			packer.packer.retransmissionQueue = conn.conn.retransmissionQueue
			packer.pnManager.EXPECT().PeekPacketNumber(level.PacketNumberSpace()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
			packer.ackFramer.EXPECT().GetAckFrame(level, gomock.Any(), false).Return(nil)
			_, payload, err := packer.packer.maybeGetCryptoPacket(1200, level, monotime.Now(), false, false, protocol.Version1)
			require.NoError(t, err)
			require.NotEmpty(t, payload.frames)
			recovery := conn.conn.cryptoRecovery(level)
			require.NotEmpty(t, recovery.sent, "only the native packet preparation can mark these bytes sent")
			recovery.OnAcked(&wire.CryptoFrame{Offset: 2, Data: data[2:5]})
			for range 2 {
				eliciting, _, _, err := conn.conn.handleFrames([]byte{1}, protocol.ConnectionID{}, level, nil, monotime.Now())
				require.NoError(t, err)
				require.True(t, eliciting)
				require.Equal(t, []CryptoRange{{Length: 2}, {Offset: 5, Length: len(data) - 5}}, recovery.pending,
					"peer PING must neither resurrect acknowledged bytes nor duplicate pending ranges")
			}
		})
	}
}
