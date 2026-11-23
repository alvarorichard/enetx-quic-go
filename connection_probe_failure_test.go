package quic

import (
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	mockackhandler "github.com/enetx/quic-go/internal/mocks/ackhandler"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestProbePacketPreparationPreservesFailureWithoutSending(t *testing.T) {
	for _, stage := range []string{"recovery", "queued", "empty"} {
		t.Run(stage, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			handler := mockackhandler.NewMockSentPacketHandler(ctrl)
			conn := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{
				InitialCryptoRecovery: stage == "recovery",
			}}, false, connectionOptSentPacketHandler(handler))
			cause := errors.New("probe packet preparation failed")
			handler.EXPECT().QueueProbePacket(protocol.PacketNumberSpaceInitial).Return(stage == "queued")
			conn.packer.EXPECT().PackPTOProbePacket(protocol.EncryptionInitial, gomock.Any(), stage == "empty", gomock.Any(), protocol.Version1).Return(nil, cause)
			require.ErrorIs(t, conn.conn.sendProbePacket(ackhandler.SendPTOInitial, monotime.Now()), cause)
		})
	}
}

func TestCoalescedProbeRequiresItsNativePackerAndAnActiveProbeBudget(t *testing.T) {
	ctrl := gomock.NewController(t)
	handler := mockackhandler.NewMockSentPacketHandler(ctrl)
	conn := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{CoalescePTOProbes: true}},
		false, connectionOptSentPacketHandler(handler))
	handled, err := conn.conn.sendCoalescedPTOProbe(monotime.Now())
	require.True(t, handled)
	require.ErrorContains(t, err, "requires the connection packet packer")
	conn.conn.packer = newTestPacketPacker(t, ctrl, protocol.PerspectiveClient).packer
	handled, err = conn.conn.sendCoalescedPTOProbe(monotime.Now())
	require.False(t, handled, "ordinary sent-packet handlers without an active coalesced budget keep the native path")
	require.NoError(t, err)
}

func TestInitialProtectionPreservesAnEncodingFailure(t *testing.T) {
	cause := errors.New("Initial control frame encoding failed")
	packer := &packetPacker{initialProtection: &InitialPacketProtection{}, rand: *rand.New(rand.NewPCG(1, 2))}
	crypto := &wire.CryptoFrame{Data: []byte("handshake bytes")}
	payload := payload{
		frames: []ackhandler.Frame{{Frame: crypto}, {Frame: failingPacketFrame{cause}}},
		length: crypto.Length(protocol.Version1) + 1,
	}
	data, _, err := packer.appendProtectedInitial(nil, payload, 100, protocol.Version1)
	require.Nil(t, data, "a failed protected frame must never publish a partial packet")
	require.ErrorIs(t, err, cause)
}

func TestHandshakeProbeOmitsAnEmptyFollowupAfterItsFirstDatagram(t *testing.T) {
	ctrl := gomock.NewController(t)
	conn := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{
		HandshakeProbeOnlyWithData: true, HandshakeProbePackets: 2,
	}}, false)
	handler := conn.conn.sentPacketHandler
	now := monotime.Now()
	handler.DropPackets(protocol.EncryptionInitial, now)
	require.NoError(t, handler.OnLossDetectionTimeout(now))
	pn := handler.PopPacketNumber(protocol.PacketNumberSpaceHandshake)
	handler.SentPacket(now, pn, protocol.InvalidPacketNumber, nil,
		[]ackhandler.Frame{{Frame: &wire.PingFrame{}, Handler: emptyHandler{}}},
		protocol.EncryptionHandshake, protocol.ECNNon, 100, false, false)
	require.Equal(t, ackhandler.SendPTOHandshake, handler.SendMode(now))
	conn.packer.EXPECT().PackPTOProbePacket(protocol.EncryptionHandshake, gomock.Any(), false, gomock.Any(), protocol.Version1).Return(nil, nil)
	require.NoError(t, conn.conn.sendProbePacket(ackhandler.SendPTOHandshake, now))
	require.NotEqual(t, ackhandler.SendPTOHandshake, handler.SendMode(now), "an empty follow-up cannot retain the probe allowance")
}
