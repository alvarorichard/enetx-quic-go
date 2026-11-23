package wire

import (
	"bytes"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestLegacyAckFrequencyRejectsInvalidFieldsWithoutPartialFrame(t *testing.T) {
	for _, frame := range []LegacyAckFrequencyFrame{
		{SequenceNumber: quicvarint.Max + 1, AckElicitingThreshold: 1},
		{AckElicitingThreshold: 0},
		{AckElicitingThreshold: quicvarint.Max + 1},
		{AckElicitingThreshold: 1, RequestMaxAckDelay: -time.Nanosecond},
	} {
		prefix := []byte("previous frame")
		got, err := frame.Append(bytes.Clone(prefix), protocol.Version1)
		require.Error(t, err)
		require.Equal(t, prefix, got)
	}
}
