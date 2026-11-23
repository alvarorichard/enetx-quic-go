package ackhandler

import (
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/monotime"
	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/utils"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestNativeECNCongestionQueuesACKWithCustomThreshold(t *testing.T) {
	tracker := policyTracker(&AckPolicy{PacketThreshold: 10, ECN: AckECNNative}, 0)
	now := monotime.Now()
	require.NoError(t, tracker.ReceivedPacket(0, protocol.ECNCE, now, true))
	require.True(t, tracker.ackQueued)
	ack := tracker.GetAckFrame(now, true)
	require.NotNil(t, ack)
	require.True(t, ack.AcksPacket(0))
	require.EqualValues(t, 1, ack.ECNCE)
}

func TestPTOWithoutInitialKeysUsesHandshakeAndPreservesNumberGap(t *testing.T) {
	handler := NewSentPacketHandler(
		0, 1252, utils.NewRTTStats(), &utils.ConnectionStats{},
		false, false, nil, protocol.PerspectiveClient, nil, utils.DefaultLogger,
		ClientSendConfig{
			CoalescePTOProbes: true, SeparatePacketNumberSpaces: true,
			HandshakeProbeSkipPacketNumber: true,
		},
	).(*sentPacketHandler)
	now := monotime.Now()
	handler.DropPackets(protocol.EncryptionInitial, now)
	require.False(t, SkipEmptyHandshakeProbe(nil))
	require.False(t, SkipEmptyHandshakeProbe(handler))
	require.NoError(t, handler.OnLossDetectionTimeout(now))
	require.Equal(t, SendPTOHandshake, handler.ptoMode)
	require.False(t, SkipEmptyHandshakeProbe(handler), "the first probe must still be allowed")
	require.EqualValues(t, 1, handler.PopPacketNumber(protocol.PacketNumberSpaceHandshake))
	force, ok := BeginPTOProbeDatagram(handler, 1252)
	require.True(t, ok)
	require.Equal(t, [3]bool{false, true, false}, force)
	require.True(t, SkipEmptyHandshakeProbe(handler), "the default two-probe allowance can suppress its empty follow-up")
	require.Zero(t, handler.numProbesToSend)
	require.False(t, SkipEmptyHandshakeProbe(handler))
}

func TestStreamProbeCopiesLegacyAndRangeHandlersWithoutDuplicateLoss(t *testing.T) {
	for _, modern := range []bool{false, true} {
		handler := streamRecoveryHandler(t)
		now := monotime.Now()
		controlLoss, streamLoss := 0, 0
		legacy := &customFrameHandler{onLost: func(wire.Frame) { streamLoss++ }}
		ranges := &probeStreamRecorder{useful: true}
		var streamHandler FrameHandler = legacy
		if modern {
			streamHandler = ranges
		}

		pn := handler.PopPacketNumber(protocol.PacketNumberSpaceAppData)
		handler.SentPacket(now, pn, protocol.InvalidPacketNumber,
			[]StreamFrame{{Frame: &wire.StreamFrame{Data: []byte("payload")}, Handler: streamHandler}},
			[]Frame{{Frame: &wire.PingFrame{}, Handler: &customFrameHandler{onLost: func(wire.Frame) { controlLoss++ }}}},
			protocol.Encryption1RTT, protocol.ECNNon, 100, false, false,
		)
		require.True(t, handler.QueueProbePacket(protocol.PacketNumberSpaceAppData))
		require.False(t, handler.QueueProbePacket(protocol.PacketNumberSpaceAppData))
		require.Equal(t, 1, controlLoss)
		if modern {
			require.Equal(t, 1, ranges.probed)
			require.Zero(t, ranges.lost)
		} else {
			require.Equal(t, 1, streamLoss)
		}
	}
}

func TestCoalescedProbeNotifiesLegacyAndRangeStreamHandlers(t *testing.T) {
	handler := newBatchHandler(t)
	legacyLoss := 0
	ranges := &probeStreamRecorder{useful: true}
	p := &packet{StreamFrames: []StreamFrame{
		{Frame: &wire.StreamFrame{Data: []byte("legacy")}, Handler: &customFrameHandler{onLost: func(wire.Frame) { legacyLoss++ }}},
		{Frame: &wire.StreamFrame{Data: []byte("range")}, Handler: ranges},
	}}
	require.True(t, handler.queueStreamProbeFrames(p))
	require.Equal(t, 1, legacyLoss)
	require.Nil(t, p.StreamFrames[0].Handler)
	require.Same(t, ranges, p.StreamFrames[1].Handler)
	require.Equal(t, 1, ranges.probed)
	require.Zero(t, ranges.lost)
}

func TestPacketHistoryIteratorHonorsEarlyStop(t *testing.T) {
	handler := newBatchHandler(t)
	visited := 0
	for history := range handler.histories() {
		require.Same(t, handler.history(protocol.PacketNumberSpaceInitial), history)
		visited++
		break
	}

	require.Equal(t, 1, visited)
}

func TestLostPacketNumberMappingExpiresWithItsMetadata(t *testing.T) {
	tracker := newLostPacketTracker()
	tracker.Add(2, monotime.Now(), 100, 9)
	require.EqualValues(t, 9, tracker.CongestionNumber(2))
	require.EqualValues(t, 20, tracker.CongestionNumber(20))
	tracker.Reset()
	require.EqualValues(t, 2, tracker.CongestionNumber(2), "expired mappings cannot leak into later loss accounting")
}

func TestAckPolicyEmptyHistoryAndDebugTimerPreserveThreshold(t *testing.T) {
	for _, policy := range []*AckPolicy{nil, {PacketThreshold: 10}} {
		tracker := policyTracker(policy, 0)
		require.False(t, tracker.withinMissingPacketWindow(8), "an unused tracker has no missing packet range")
		tracker.logger = utils.DefaultLogger.WithPrefix("ack-policy-boundary")
		tracker.logger.SetLogLevel(utils.LogLevelDebug)
		now := monotime.Now()
		require.NoError(t, tracker.ReceivedPacket(0, protocol.ECNNon, now, true))
		require.False(t, tracker.ackQueued)
		require.Equal(t, now.Add(tracker.maxAckDelay()), tracker.ackAlarm)
		require.Nil(t, tracker.GetAckFrame(now, true), "debug logging cannot advance the ACK timer")
		ack := tracker.GetAckFrame(tracker.ackAlarm, true)
		require.NotNil(t, ack)
		require.True(t, ack.AcksPacket(0))
	}
}
