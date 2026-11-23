package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func boundarySender(config SenderConfig) (*configuredSender, *mockClock) {
	var clock mockClock
	return newConfiguredSender(&clock, new(utils.RTTStats), new(utils.ConnectionStats), 1200, config, nil), &clock
}

func TestConfiguredCongestionWindowFloorsTrackPathMTU(t *testing.T) {
	for _, algorithm := range []Algorithm{AlgorithmReno, AlgorithmCubic, AlgorithmCubicBytes} {
		t.Run(map[Algorithm]string{AlgorithmReno: "reno", AlgorithmCubic: "rfc-cubic", AlgorithmCubicBytes: "byte-cubic"}[algorithm], func(t *testing.T) {
			sender, clock := boundarySender(SenderConfig{Algorithm: algorithm, InitialWindowPackets: 2})
			OnPacketSent(sender, clock.Now(), 0, 1, 1200, true)
			OnCongestionEvent(sender, 1, 1200, 1200)
			require.EqualValues(t, 2400, sender.GetCongestionWindow(), "a loss may not reduce the two-packet floor")
			require.EqualValues(t, 2400, sender.connStats.CongestionWindow.Load())

			sender.SetMaxDatagramSize(1400)
			require.EqualValues(t, 2800, sender.GetCongestionWindow(), "an MTU-relative minimum must follow the new path size")
			require.EqualValues(t, 2800, sender.connStats.CongestionWindow.Load())
		})
	}
}

func TestConfiguredRenoHonorsPacketCeilingInSlowStartAndAvoidance(t *testing.T) {
	for _, avoidance := range []bool{false, true} {
		t.Run(map[bool]string{false: "slow-start", true: "avoidance"}[avoidance], func(t *testing.T) {
			sender, clock := boundarySender(SenderConfig{Algorithm: AlgorithmReno, SlowStart: SlowStartHybrid,
				InitialWindowPackets: 2, MaxWindowPackets: 3})
			if avoidance {
				OnPacketSent(sender, clock.Now(), 0, 1, 1200, true)
				OnCongestionEvent(sender, 1, 1200, 1200)
				require.False(t, sender.InSlowStart())
			}

			OnPacketSent(sender, clock.Now(), 0, 2, 1200, true)
			OnPacketSent(sender, clock.Now(), 1200, 3, 1200, true)
			clock.Advance(50 * time.Millisecond)
			OnPacketAcked(sender, 2, 1200, 2400, clock.Now())
			OnPacketAcked(sender, 3, 1200, 1200, clock.Now())
			require.EqualValues(t, 3600, sender.GetCongestionWindow())
			require.EqualValues(t, 3600, sender.connStats.CongestionWindow.Load())
		})
	}
}

func TestSpuriousLatestLossDoesNotExitAnEarlierRecovery(t *testing.T) {
	sender, clock := boundarySender(SenderConfig{Algorithm: AlgorithmReno})
	for packet := protocol.PacketNumber(1); packet <= 5; packet++ {
		OnPacketSent(sender, clock.Now(), protocol.ByteCount(packet-1)*1200, packet, 1200, true)
	}

	OnPacketAcked(sender, 2, 1200, 6000, clock.Now())
	OnCongestionEvent(sender, 1, 1200, 4800)
	firstWindow := sender.GetCongestionWindow()
	OnPacketSent(sender, clock.Now(), 3600, 6, 1200, true)
	OnCongestionEvent(sender, 6, 1200, 4800)
	require.Less(t, sender.GetCongestionWindow(), firstWindow)
	sender.OnSpuriousLoss(6)
	require.Equal(t, firstWindow, sender.GetCongestionWindow())
	require.EqualValues(t, firstWindow, sender.connStats.CongestionWindow.Load())
	require.True(t, sender.InRecovery(), "undoing a later cutback cannot acknowledge the earlier recovery boundary")
	require.EqualValues(t, 5, sender.largestSentAtLastCutback)
}

func TestTimeoutWithoutRetransmissionPreservesWindowButDiscardsUndo(t *testing.T) {
	sender, clock := boundarySender(SenderConfig{Algorithm: AlgorithmReno, PRR: true})
	OnPacketSent(sender, clock.Now(), 0, 1, 1200, true)
	OnCongestionEvent(sender, 1, 1200, 1200)
	window, threshold := sender.GetCongestionWindow(), sender.slowStartThreshold
	require.True(t, sender.undoState.IsActive())
	sender.OnRetransmissionTimeout(false)
	require.Equal(t, window, sender.GetCongestionWindow())
	require.Equal(t, threshold, sender.slowStartThreshold)
	require.False(t, sender.undoState.IsActive())
	require.Zero(t, sender.prr)
	require.Equal(t, protocol.InvalidPacketNumber, sender.largestSentAtLastCutback)
}

func TestMigrationReinitializesPacingCredit(t *testing.T) {
	config := PacingConfig{Algorithm: PacingLeakyBucket, BurstPackets: 3, SlowStartGain: 1000, AvoidanceGain: 1000}
	sender, clock := boundarySender(SenderConfig{Algorithm: AlgorithmReno, Pacing: &config})
	sender.rttStats.UpdateRTT(50*time.Millisecond, 0)
	OnPacketSent(sender, clock.Now(), 0, 1, 1200, true)
	old := sender.pacing
	require.Less(t, old.credit, old.capacity)
	clock.Advance(time.Second)
	sender.OnConnectionMigration()
	require.NotSame(t, old, sender.pacing)
	require.Equal(t, config, sender.pacing.config)
	require.EqualValues(t, 3600, sender.pacing.credit)
	require.Equal(t, clock.Now(), sender.pacing.updated)
	require.Equal(t, sender.initialCongestionWindow, sender.GetCongestionWindow())
	require.False(t, sender.InRecovery())
}

func TestPacingArithmeticSaturatesAtRepresentableLimits(t *testing.T) {
	require.Equal(t, time.Duration(math.MaxInt64), transferTime(1, 0))
	require.Equal(t, 125*time.Millisecond, transferTime(125, 1000*bytesPerSecond))
	require.EqualValues(t, uint64(math.MaxUint64), saturatingMultiply(math.MaxUint64, 2))
	require.EqualValues(t, uint64(math.MaxUint64), saturatingMultiply(math.MaxUint64, 1))
	require.Zero(t, saturatingMultiply(math.MaxUint64, 0))

	sender, _ := boundarySender(SenderConfig{Algorithm: AlgorithmReno, MaxWindowPackets: -1})
	// A model state near QUIC's valid byte-count ceiling avoids billions of
	// simulated growth rounds. The RTT and gain remain in accepted ranges.
	sender.congestionWindow = protocol.MaxByteCount
	sender.rttStats.UpdateRTT(time.Nanosecond, 0)
	policy := &pacingPolicy{config: PacingConfig{SlowStartGain: 10000, AvoidanceGain: 10000}}
	require.EqualValues(t, uint64(math.MaxUint64), policy.rate(sender))
	require.EqualValues(t, uint64(math.MaxUint64), policy.leakyFactor(sender))
}
