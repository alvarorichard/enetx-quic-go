package quic

import (
	"errors"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestTryAcceptStreamRetainsOrderAndCloseErrors(t *testing.T) {
	m := newIncomingStreamsMap(protocol.StreamTypeUni,
		func(id protocol.StreamID) *mockStream { return &mockStream{id: id} },
		4, false, func(wire.Frame) {}, protocol.PerspectiveClient)
	_, err := m.TryAcceptStream()
	require.ErrorIs(t, err, ErrWouldBlock)
	_, err = m.GetOrOpenStream(7)
	require.NoError(t, err)
	for _, id := range []protocol.StreamID{3, 7} {
		str, err := m.TryAcceptStream()
		require.NoError(t, err)
		require.Equal(t, id, str.id)
	}

	_, err = m.TryAcceptStream()
	require.ErrorIs(t, err, ErrWouldBlock)
	closed := errors.New("closed fixture connection")
	m.CloseWithError(closed)
	_, err = m.TryAcceptStream()
	require.ErrorIs(t, err, closed)
}

func TestTryAcceptUniStreamRejectsRetiredEarlyGeneration(t *testing.T) {
	conn := &Conn{streamsMap: &streamsMap{reset: true}}
	_, err := conn.TryAcceptUniStream()
	require.ErrorIs(t, err, Err0RTTRejected)
}
