package http3

import (
	"context"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestLegacyQPACKFeedbackBoundsAnUnreadDecoderStream(t *testing.T) {
	conn, peer := newConnPair(t, withServerStreamWindow(32))
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	owner.configureQPACK(orderedTestSettings(map[uint64]uint64{1: 128, 7: 1}))
	require.NoError(t, owner.qpackDecoder.Cancel(0))
	stream, err := peer.AcceptUniStream(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte{3}, qpackBatchRead(t, stream, 1))
	// Leave the peer's decoder stream unread. Connection-level feedback must
	// remain bounded when its asynchronous writer exhausts stream credit.
	for id := uint64(4); id < 16384; id += 4 {
		err = owner.qpackDecoder.Cancel(id)
		if err != nil {
			break
		}
	}

	require.ErrorIs(t, err, errQPACKFeedbackBacklog)
	owner.qpackCancellation(16384)()
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeExcessiveLoad), closed.ErrorCode)
}

func TestLegacyQPACKFeedbackDoesNotReopenAClosedConnection(t *testing.T) {
	conn, _ := newConnPair(t)
	require.NoError(t, conn.CloseWithError(77, "connection closed before decoder setup"))
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	feedback := make(chan []byte, 1)
	feedback <- []byte{0x40}
	finished := make(chan struct{})
	go func() { owner.writeQPACKFeedback(feedback); close(finished) }()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("feedback writer did not stop after connection shutdown")
	}

	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.EqualValues(t, 77, closed.ErrorCode, "feedback cannot replace the established shutdown cause")
}

func TestRetiredGenerationCannotAppendToItsFullFeedbackQueue(t *testing.T) {
	conn, _ := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	feedback := make(chan []byte, 1)
	first, abandoned := []byte{0x40}, []byte{0x44}
	require.NoError(t, owner.enqueueQPACKFeedback(feedback, first))
	require.ErrorIs(t, owner.enqueueQPACKFeedback(feedback, abandoned), errQPACKFeedbackBacklog)
	owner.retireEarlyData()
	require.ErrorIs(t, owner.enqueueQPACKFeedback(feedback, abandoned), quic.Err0RTTRejected)
	require.Equal(t, first, <-feedback, "retirement must not replace already accepted feedback")
	require.Empty(t, feedback)
	require.NoError(t, conn.Context().Err(), "retiring the HTTP/3 generation cannot close the authenticated QUIC owner")
}
