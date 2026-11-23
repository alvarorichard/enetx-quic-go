package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
)

func TestBandwidthSaturatesAfterDivisionWithoutMultiplicationOverflow(t *testing.T) {
	const maximum = uint64(math.MaxUint64 / uint64(bytesPerSecond) * uint64(bytesPerSecond))
	// The product fits 64 bits; converting its quotient to bit/s would overflow.
	got := saturatedBandwidthFromDelta(protocol.ByteCount(1<<32), time.Nanosecond)
	require.EqualValues(t, maximum, got)
	pacer := newPacer(initialMaxDatagramSize)
	require.Zero(t, pacer.timeScaledBandwidth(time.Second, 0), "a zero pacing rate must not accrue credit")
}
