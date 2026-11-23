package quic_test

import (
	"math"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-quic-go"
	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/quicvarint"
	"github.com/alvarorichard/enetx-quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

// Standalone validation must reject invalid public policies before opening a
// socket or invoking callbacks. Boundary values remain usable independently.
func TestClientHandshakePolicyValidationBoundaries(t *testing.T) {
	type invalidPolicy struct {
		name   string
		policy quic.ClientHandshake
		field  string
	}

	cases := []invalidPolicy{
		{"initial-pto-overflow", quic.ClientHandshake{InitialPTOMultiplier: 17}, "initial PTO"},
		{"initial-probe-overflow", quic.ClientHandshake{InitialCryptoRecovery: true, InitialCryptoProbePackets: 3}, "Initial CRYPTO"},
		{"initial-probe-without-recovery", quic.ClientHandshake{InitialCryptoProbePackets: 1}, "Initial CRYPTO"},
		{"initial-peer-probe-without-recovery", quic.ClientHandshake{InitialCryptoResendOnPeerProbe: true}, "Initial CRYPTO"},
		{"initial-layout-without-recovery", quic.ClientHandshake{InitialCryptoRecoveryLayout: func(quic.InitialCryptoLayoutInfo) [][]quic.CryptoRange { return nil }}, "Initial CRYPTO"},
		{"handshake-probe-overflow", quic.ClientHandshake{HandshakeProbePackets: 3}, "PTO probe"},
		{"application-probe-overflow", quic.ClientHandshake{ApplicationProbePackets: 3}, "PTO probe"},
		{"handshake-peer-probe-without-recovery", quic.ClientHandshake{HandshakeCryptoResendOnPeerProbe: true}, "Handshake CRYPTO"},
		{"negative-rtt", quic.ClientHandshake{InitialRTT: -1}, "initial RTT"},
		{"rtt-scaling-overflow", quic.ClientHandshake{InitialRTT: time.Duration(math.MaxInt64/16 + 1)}, "initial RTT"},
		{"unknown-congestion", quic.ClientHandshake{CongestionControl: quic.CongestionControlAlgorithm(255)}, "congestion control"},
		{"unknown-slow-start", quic.ClientHandshake{SlowStart: quic.SlowStartAlgorithm(255)}, "slow start"},
		{"short-segment", quic.ClientHandshake{CongestionControlSegmentSize: 1199}, "segment size"},
		{"large-segment", quic.ClientHandshake{CongestionControlSegmentSize: 65528}, "segment size"},
		{"too-many-connections", quic.ClientHandshake{CongestionControlConnections: 17}, "connection count"},
		{"connection-emulation-with-reno", quic.ClientHandshake{CongestionControl: quic.CongestionControlReno, CongestionControlConnections: 2}, "connection count"},
		{"connection-emulation-with-rfc-cubic", quic.ClientHandshake{CongestionControl: quic.CongestionControlCubic, CongestionControlConnections: 2}, "connection count"},
		{"single-packet-initial-window", quic.ClientHandshake{InitialCongestionWindowPackets: 1}, "initial congestion window"},
		{"large-initial-window", quic.ClientHandshake{InitialCongestionWindowPackets: protocol.MaxCongestionWindowPackets + 1}, "initial congestion window"},
		{"negative-window-limit", quic.ClientHandshake{MaxCongestionWindowPackets: -2}, "maximum congestion window"},
		{"single-packet-window-limit", quic.ClientHandshake{MaxCongestionWindowPackets: 1}, "maximum congestion window"},
		{"window-limit-overflow", quic.ClientHandshake{MaxCongestionWindowPackets: 1 << 32}, "maximum congestion window"},
		{"implicit-initial-window-above-limit", quic.ClientHandshake{MaxCongestionWindowPackets: 31}, "initial congestion window exceeds"},
		{"explicit-initial-window-above-limit", quic.ClientHandshake{InitialCongestionWindowPackets: 3, MaxCongestionWindowPackets: 2}, "initial congestion window exceeds"},
		{"large-recovery-burst", quic.ClientHandshake{RecoveryBurstPackets: 17}, "recovery policy"},
		{"large-persistent-congestion-threshold", quic.ClientHandshake{PersistentCongestionThreshold: 17}, "recovery policy"},
		{"negative-legacy-delay", quic.ClientHandshake{LegacyAckFrequencyMinDelay: -1}, "minimum delay"},
		{"fractional-legacy-delay", quic.ClientHandshake{LegacyAckFrequencyMinDelay: time.Microsecond + 1}, "minimum delay"},
		{"legacy-delay-above-native-maximum", quic.ClientHandshake{LegacyAckFrequencyMinDelay: 26 * time.Millisecond}, "minimum delay"},
		{"legacy-delay-above-explicit-maximum", quic.ClientHandshake{MaxAckDelay: time.Millisecond, LegacyAckFrequencyMinDelay: 2 * time.Millisecond}, "minimum delay"},
		{"unknown-padding", quic.ClientHandshake{InitialPaddingMode: quic.InitialPaddingMode(255)}, "padding mode"},
		{"single-window-divisor", quic.ClientHandshake{ReceiveWindowUpdateDivisor: 1}, "receive-window divisor"},
		{"negative-ping-threshold", quic.ClientHandshake{AckOnlyPingThreshold: -2}, "ACK probe"},
		{"negative-data-threshold", quic.ClientHandshake{AckOnlyMaxDataThreshold: -1}, "ACK probe"},
		{"conflicting-static-probes", quic.ClientHandshake{AckOnlyPingThreshold: 1, AckOnlyMaxDataThreshold: 1}, "ACK probe"},
		{"conflicting-ping-callback", quic.ClientHandshake{AckOnlyPingThreshold: 1, AckProbePolicy: func(quic.AckProbeInfo) bool { return false }}, "ACK probe"},
		{"conflicting-data-callback", quic.ClientHandshake{AckOnlyMaxDataThreshold: 1, AckProbePolicy: func(quic.AckProbeInfo) bool { return false }}, "ACK probe"},
		{"invalid-initial-protection", quic.ClientHandshake{InitialPacketProtection: &quic.InitialPacketProtection{MinCryptoSplits: -1}}, "protection range"},
		{"small-udp", quic.ClientHandshake{MaxUDPPayloadSize: 1199}, "UDP payload"},
		{"large-udp", quic.ClientHandshake{MaxUDPPayloadSize: 65528}, "UDP payload"},
		{"single-cid", quic.ClientHandshake{ActiveConnectionIDLimit: 1}, "connection ID limit"},
		{"cid-limit-overflow", quic.ClientHandshake{ActiveConnectionIDLimit: quicvarint.Max + 1}, "connection ID limit"},
		{"submillisecond-ack-delay", quic.ClientHandshake{MaxAckDelay: time.Millisecond - 1}, "max ACK delay"},
		{"fractional-ack-delay", quic.ClientHandshake{MaxAckDelay: time.Millisecond + 1}, "max ACK delay"},
		{"large-ack-delay", quic.ClientHandshake{MaxAckDelay: protocol.MaxMaxAckDelay + time.Millisecond}, "max ACK delay"},
		{"invalid-ack-policy", quic.ClientHandshake{AckPolicy: &quic.AckPolicy{MinDelay: -1}}, "ACK minimum delay"},
		{"omitted-nondefault-udp", quic.ClientHandshake{OmitMaxUDPPayloadSize: true, MaxUDPPayloadSize: 1200}, "omitted UDP"},
		{"duplicate-layout", quic.ClientHandshake{TransportParameters: &transportparams.Layout{Order: []uint64{4, 4}}}, "duplicate transport parameter"},
		{"short-initial-cid", quic.ClientHandshake{InitialDestinationConnectionIDLength: 7}, "connection ID length"},
		{"long-initial-cid", quic.ClientHandshake{InitialDestinationConnectionIDLength: 21}, "connection ID length"},
		{"packet-number-overflow", quic.ClientHandshake{InitialPacketNumber: quicvarint.Max + 1}, "packet number"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.ErrorContains(t, tc.policy.Validate(), tc.field)
		})
	}

	valid := map[string]*quic.ClientHandshake{
		"nil":                          nil,
		"defaults":                     {},
		"minimum-rtt":                  {InitialRTT: 1},
		"maximum-rtt-scaling":          {InitialRTT: time.Duration(math.MaxInt64 / 16), InitialPTOMultiplier: 16},
		"bounded-probes":               {InitialCryptoRecovery: true, InitialCryptoProbePackets: 2, HandshakeCryptoRecovery: true, HandshakeProbePackets: 2, ApplicationProbePackets: 2},
		"minimum-window":               {InitialCongestionWindowPackets: 2, MaxCongestionWindowPackets: 2},
		"maximum-initial-window":       {InitialCongestionWindowPackets: protocol.MaxCongestionWindowPackets},
		"maximum-window":               {MaxCongestionWindowPackets: math.MaxUint32},
		"unbounded-window":             {MaxCongestionWindowPackets: -1},
		"minimum-segment":              {CongestionControlSegmentSize: 1200},
		"maximum-segment":              {CongestionControlSegmentSize: 65527},
		"maximum-connection-emulation": {CongestionControl: quic.CongestionControlCubicBytes, CongestionControlConnections: 16},
		"maximum-recovery-policy":      {RecoveryBurstPackets: 16, PersistentCongestionThreshold: 16},
		"legacy-native-delay-bound":    {LegacyAckFrequencyMinDelay: 25 * time.Millisecond},
		"legacy-explicit-delay-bound":  {MaxAckDelay: time.Millisecond, LegacyAckFrequencyMinDelay: time.Millisecond},
		"minimum-udp":                  {MaxUDPPayloadSize: 1200},
		"maximum-udp":                  {MaxUDPPayloadSize: 65527},
		"omitted-default-udp":          {OmitMaxUDPPayloadSize: true, MaxUDPPayloadSize: 65527},
		"minimum-cid-limit":            {ActiveConnectionIDLimit: 2},
		"maximum-cid-limit":            {ActiveConnectionIDLimit: quicvarint.Max},
		"minimum-ack-delay":            {MaxAckDelay: time.Millisecond},
		"maximum-ack-delay":            {MaxAckDelay: protocol.MaxMaxAckDelay},
		"minimum-cid":                  {InitialDestinationConnectionIDLength: 8},
		"maximum-cid":                  {InitialDestinationConnectionIDLength: 20},
		"maximum-packet-number":        {InitialPacketNumber: quicvarint.Max},
		"disabled-ping":                {AckOnlyPingThreshold: -1},
	}

	for name, policy := range valid {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, policy.Validate())
		})
	}
}

func TestClientHandshakePacingValidationBoundaries(t *testing.T) {
	valid := quic.PacingConfig{
		Algorithm: quic.PacingScheduled, BurstPackets: 1, LumpyPackets: 1,
		SlowStartGain: 1, AvoidanceGain: 1,
	}

	invalid := map[string]func(*quic.PacingConfig){
		"algorithm":       func(p *quic.PacingConfig) { p.Algorithm = quic.PacingAlgorithm(255) },
		"zero-burst":      func(p *quic.PacingConfig) { p.BurstPackets = 0 },
		"large-burst":     func(p *quic.PacingConfig) { p.BurstPackets = 10001 },
		"zero-lumpy":      func(p *quic.PacingConfig) { p.LumpyPackets = 0 },
		"large-lumpy":     func(p *quic.PacingConfig) { p.LumpyPackets = 10001 },
		"window-fraction": func(p *quic.PacingConfig) { p.LumpyWindowFraction = 1001 },
		"negative-timer":  func(p *quic.PacingConfig) { p.Granularity = -1 },
		"large-timer":     func(p *quic.PacingConfig) { p.Granularity = time.Second + 1 },
		"zero-slow-gain":  func(p *quic.PacingConfig) { p.SlowStartGain = 0 },
		"large-slow-gain": func(p *quic.PacingConfig) { p.SlowStartGain = 10001 },
		"zero-gain":       func(p *quic.PacingConfig) { p.AvoidanceGain = 0 },
		"large-gain":      func(p *quic.PacingConfig) { p.AvoidanceGain = 10001 },
	}

	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			pacing := valid
			mutate(&pacing)
			policy := quic.ClientHandshake{Pacing: &pacing}
			require.ErrorContains(t, policy.Validate(), "pacing policy")
		})
	}

	for name, pacing := range map[string]quic.PacingConfig{
		"native-defaults": {},
		"minimum":         valid,
		"maximum": {
			Algorithm: quic.PacingLeakyBucket, BurstPackets: 10000, LumpyPackets: 10000,
			LumpyWindowFraction: 1000, Granularity: time.Second,
			SlowStartGain: 10000, AvoidanceGain: 10000,
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := quic.ClientHandshake{Pacing: &pacing}
			require.NoError(t, policy.Validate())
		})
	}
}
