package quic

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/enetx/quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestReceiveStreamTryPeekPreservesGapsOffsetsAndEOF(t *testing.T) {
	str := newReceiveStream(3, nil, newTestStreamFlowController(42))
	buffer := []byte("unchanged")
	n, err := str.TryPeek(buffer[:4])
	require.Zero(t, n)
	require.ErrorIs(t, err, ErrWouldBlock)
	require.Equal(t, "unchanged", string(buffer))
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{StreamID: 3, Offset: 2, Data: []byte("cd"), Fin: true}, monotime.Now()))
	_, err = str.TryPeek(buffer[:4])
	require.ErrorIs(t, err, ErrWouldBlock, "out-of-order bytes are not a complete prefix")
	require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{StreamID: 3, Data: []byte("ab")}, monotime.Now()))
	for range 2 {
		n, err = str.TryPeek(buffer[:4])
		require.NoError(t, err)
		require.Equal(t, 4, n)
		require.Equal(t, "abcd", string(buffer[:4]))
	}

	n, err = str.Read(buffer[:2])
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = str.TryPeek(buffer[:4])
	require.Equal(t, 2, n)
	require.ErrorIs(t, err, io.EOF)
	require.Equal(t, "cd", string(buffer[:2]))
}

func TestReceiveStreamTryPeekHonorsOwnershipDeadlineAndShutdown(t *testing.T) {
	str := newReceiveStream(3, nil, newTestStreamFlowController(42))
	str.readOnce <- struct{}{}
	_, err := str.TryPeek(make([]byte, 1))
	require.ErrorIs(t, err, ErrWouldBlock, "an existing reader must never be awaited")
	<-str.readOnce
	require.NoError(t, str.SetReadDeadline(time.Now().Add(-time.Second)))
	_, err = str.TryPeek(make([]byte, 1))
	require.ErrorIs(t, err, errDeadline)
	require.NoError(t, str.SetReadDeadline(time.Time{}))
	_, err = str.TryPeek(make([]byte, 1))
	require.ErrorIs(t, err, ErrWouldBlock)
	closed := errors.New("closed fixture connection")
	str.closeForShutdown(closed)
	_, err = str.TryPeek(make([]byte, 1))
	require.ErrorIs(t, err, closed)
	n, err := str.TryPeek(nil)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestReceiveStreamTryPeekReturnsCancellation(t *testing.T) {
	for _, remote := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "remote"}[remote], func(t *testing.T) {
			sender := NewMockStreamSender(gomock.NewController(t))
			str := newReceiveStream(3, sender, newTestStreamFlowController(42))
			if remote {
				require.NoError(t, str.handleResetStreamFrame(&wire.ResetStreamFrame{StreamID: 3, ErrorCode: 123}, monotime.Now()))
			} else {
				sender.EXPECT().onHasStreamControlFrame(protocol.StreamID(3), str)
				str.CancelRead(123)
			}

			n, err := str.TryPeek(make([]byte, 1))
			require.Zero(t, n)
			require.ErrorIs(t, err, &StreamError{StreamID: 3, ErrorCode: 123, Remote: remote})
		})
	}
}
