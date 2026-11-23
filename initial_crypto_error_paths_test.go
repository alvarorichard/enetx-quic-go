package quic

import (
	"bytes"
	"testing"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/enetx/quic-go/transportparams"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestInitialLayoutRejectsMalformedHelloWithoutConsumingBytes(t *testing.T) {
	stream := newInitialCryptoStream(true)
	calls := 0
	stream.layout = func(InitialCryptoLayoutInfo) [][]CryptoRange { calls++; return nil }
	malformed := []byte{1, 0, 0, 0}
	_, err := stream.Write(malformed)
	require.NoError(t, err)
	require.Error(t, stream.prepareInitialCryptoLayout(1200, 1100))
	require.Zero(t, calls)
	require.Equal(t, malformed, stream.writeBuf)
	require.Zero(t, stream.writeOffset)
	require.Nil(t, stream.layoutState)
}

func TestInitialLayoutFallsBackForAnotherHandshakeMessage(t *testing.T) {
	stream := newInitialCryptoStream(false)
	calls := 0
	stream.layout = func(InitialCryptoLayoutInfo) [][]CryptoRange { calls++; return nil }
	_, err := stream.Write([]byte{2, 0, 0, 0})
	require.NoError(t, err)
	require.NoError(t, stream.prepareInitialCryptoLayout(1200, 1100))
	require.Zero(t, calls)
	frame := stream.PopCryptoFrame(1100)
	require.NotNil(t, frame)
	require.Equal(t, []byte{2, 0, 0, 0}, frame.Data)
}

func TestInvalidCryptoRecoveryLayoutPropagatesThroughPacketPreparation(t *testing.T) {
	for _, probe := range []bool{false, true} {
		ctrl := gomock.NewController(t)
		packer := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
		recovery := &cryptoRangeRecovery{data: []byte("retained crypto"), layout: func(InitialCryptoLayoutInfo) [][]CryptoRange {
			return [][]CryptoRange{{{Offset: -1, Length: 1}}}
		}}
		packer.retransmissionQueue.initialRecovery = recovery
		packer.retransmissionQueue.addInitial(&wire.CryptoFrame{Data: recovery.data})
		before := bytes.Clone(recovery.data)
		packer.pnManager.EXPECT().PeekPacketNumber(protocol.PacketNumberSpaceInitial).Return(protocol.PacketNumber(0), protocol.PacketNumberLen1)
		packer.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).Return(nil)
		if probe {
			packer.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(ctrl), nil)
			packet, err := packer.packer.PackPTOProbePacket(protocol.EncryptionInitial, 1200, true, monotime.Now(), protocol.Version1)
			require.ErrorContains(t, err, "out of bounds")
			require.Nil(t, packet)
		} else {
			header, _, err := packer.packer.maybeGetCryptoPacket(1200, protocol.EncryptionInitial, monotime.Now(), false, false, protocol.Version1)
			require.ErrorContains(t, err, "out of bounds")
			require.Nil(t, header)
		}

		require.Equal(t, before, recovery.data)
		require.Equal(t, []CryptoRange{{Length: len(before)}}, recovery.pending)
		require.Nil(t, recovery.active)
	}
}

func TestVersionInformationPreservesUnrelatedParametersAndRecordsSwitch(t *testing.T) {
	conn := compatibleTestConn(t, protocol.Version1)
	params := &wire.TransportParameters{ClientLayout: &transportparams.Layout{
		Additional: []transportparams.Parameter{{ID: 0x173e, Value: []byte("custom")}},
	}}
	require.NoError(t, conn.configureVersionInformation(params))
	require.Equal(t, []transportparams.Parameter{{ID: 0x173e, Value: []byte("custom")}}, params.ClientLayout.Additional)
	recorder := new(events.Recorder)
	conn.qlogger = recorder
	header, packet := compatibleInitialPacket(t, conn, protocol.Version2, conn.origDestConnID)
	require.True(t, conn.acceptCompatibleVersion(header, packet))
	require.Len(t, recorder.Events(), 1)
	conn.connStateMutex.Lock()
	require.Equal(t, protocol.Version2, conn.connState.Version)
	conn.connStateMutex.Unlock()
}
