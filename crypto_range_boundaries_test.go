package quic

import (
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestRetiredCryptoRecoveryIgnoresLateAcknowledgmentsAndLoss(t *testing.T) {
	recovery := &cryptoRangeRecovery{data: []byte("transcript"), pending: []CryptoRange{{Length: 10}}}
	recovery.close()
	recovery.OnAcked(&wire.CryptoFrame{Data: []byte("late acknowledgment")})
	recovery.OnLost(&wire.CryptoFrame{Data: []byte("late retransmission")})
	require.NoError(t, recovery.prepare(1200, 1100))
	require.Nil(t, recovery.pop(1100))
	require.Nil(t, recovery.data)
	require.Nil(t, recovery.acked)
	require.Nil(t, recovery.pending)
}

func TestEmptyCryptoAcknowledgmentDoesNotAlterRetainedRanges(t *testing.T) {
	recovery := &cryptoRangeRecovery{acked: []CryptoRange{{Offset: 10, Length: 4}}}
	recovery.OnAcked(&wire.CryptoFrame{Offset: 50})
	require.Equal(t, []CryptoRange{{Offset: 10, Length: 4}}, recovery.acked)

	ranges := []CryptoRange{{Offset: 3, Length: 4}, {Offset: 12, Length: 8}}
	stream := &initialCryptoStream{layoutState: &initialCryptoLayoutState{remaining: ranges}}
	stream.consumeCryptoLayoutRange(&wire.CryptoFrame{Offset: 8, Data: make([]byte, 2)})
	require.Equal(t, ranges, stream.layoutState.remaining)
}
