package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"

	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3/qlog"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestCriticalStreamQueuesPreserveOrderAndRejectCanceledWork(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	owner := &rawConn{ctx: ctx}
	control := &clientControlWriter{owner: owner, queue: make(chan controlWrite, 1)}
	qpack := &clientQPACKStream{owner: owner, queue: make(chan []byte, 1), wake: make(chan struct{}, 1)}
	first, second := []byte{1}, []byte{2}
	require.NoError(t, control.enqueue(first))
	require.NoError(t, qpack.enqueue(first))
	require.ErrorContains(t, control.enqueue(second), "queue is full")
	require.ErrorIs(t, qpack.enqueue(second), errQPACKFeedbackBacklog)
	require.EqualValues(t, 1, control.pending.Load(), "a rejected instruction must not retain pending work")
	require.Equal(t, first, (<-control.queue).data)
	require.Equal(t, first, <-qpack.queue)
	require.Len(t, qpack.wake, 1, "queued instructions must wake their asynchronous owner")

	sentinel := errors.New("HTTP/3 generation retired")
	cancel(sentinel)
	require.ErrorIs(t, control.enqueue(second), sentinel)
	require.ErrorIs(t, qpack.enqueue(second), sentinel)
	require.Empty(t, control.queue)
	require.Empty(t, qpack.queue)
	require.EqualValues(t, 1, control.pending.Load(), "canceled work must not change earlier accounting")
}

func TestControlWriterDoesNotAcquireAClosedQlogProducer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		recorder := new(events.Recorder)
		owner := &rawConn{ctx: t.Context(), qlogger: recorder, qloggerProducers: 1}
		owner.RemoveQlogProducer()
		synctest.Wait() // The final producer closes the trace asynchronously.
		require.True(t, recorder.Closed())
		writer := &clientControlWriter{owner: owner}
		writer.run(nil) // No stream operation is allowed after the trace closes.
		require.Empty(t, recorder.Events())
		require.Zero(t, owner.qloggerProducers)
	})
}

func TestWireFrameRecordingStopsAtMalformedBoundary(t *testing.T) {
	reserved := quicvarint.Append(nil, 33)
	reserved = append(quicvarint.Append(reserved, 2), 'o', 'k')
	priorityPayload := append(quicvarint.Append(nil, 8), []byte("u=1")...)
	priority := quicvarint.Append(nil, 0xf0700)
	priority = append(quicvarint.Append(priority, uint64(len(priorityPayload))), priorityPayload...)
	complete := append(bytes.Clone(reserved), priority...)
	for name, suffix := range map[string][]byte{
		"truncated-type":      {0x40},
		"truncated-length":    {33, 0x40},
		"truncated-payload":   {33, 2, 1},
		"missing-priority-id": append(quicvarint.Append(nil, 0xf0700), 0),
	} {
		t.Run(name, func(t *testing.T) {
			recorder := new(events.Recorder)
			recordWireFrames(recorder, quic.StreamID(2), append(bytes.Clone(complete), suffix...))
			recorded := recorder.Events()
			require.Len(t, recorded, 2, "malformed trailing bytes must not invent a qlog frame")
			first := recorded[0].(qlog.FrameCreated)
			require.EqualValues(t, 2, first.StreamID)
			require.Equal(t, len(reserved), first.Raw.Length)
			require.Equal(t, 2, first.Raw.PayloadLength)
			require.Equal(t, qlog.ReservedFrame{Type: 33}, first.Frame.Frame)
			second := recorded[1].(qlog.FrameCreated)
			require.Equal(t, len(priority), second.Raw.Length)
			require.Equal(t, qlog.PriorityUpdateFrame{StreamID: 8, PriorityFieldValue: "u=1"}, second.Frame.Frame)
		})
	}
}

func TestControlStreamRejectsPushPriorityUpdate(t *testing.T) {
	conn, peer := newConnPair(t)
	(&Transport{}).NewClientConn(conn)
	stream, err := peer.OpenUniStream()
	require.NoError(t, err)
	data := (&settingsFrame{MaxFieldSectionSize: -1}).Append([]byte{0})
	data = append(data, append(quicvarint.Append(nil, 0xf0701), 1, 0)...)
	_, err = stream.Write(data)
	require.NoError(t, err)
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("push priority update did not close the HTTP/3 connection")
	}

	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeFrameUnexpected), closed.ErrorCode)
}

func TestExtensionPayloadDrainRetainsReadFailure(t *testing.T) {
	cause := errors.New("extension payload read failed")
	parser := &frameParser{
		r:              io.MultiReader(bytes.NewReader([]byte{33, 1}), iotest.ErrReader(cause)),
		onUnknownFrame: func(ControlFrame) error { return nil },
	}
	frame, err := parser.ParseNext(nil)
	require.Nil(t, frame)
	require.ErrorIs(t, err, cause)
}

func TestQueuedControlWriteStopsOnPeerCancellationAfterAnEmptyWrite(t *testing.T) {
	conn, peer := newConnPair(t, withServerStreamWindow(32))
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	stream, err := conn.OpenUniStream()
	require.NoError(t, err)
	writer := &clientControlWriter{owner: owner, queue: make(chan controlWrite, 3)}
	require.NoError(t, writer.enqueue(nil))
	require.NoError(t, writer.enqueue([]byte{0, 4, 0})) // Control type, empty SETTINGS.
	require.NoError(t, writer.enqueue(bytes.Repeat([]byte{33, 0}, 32768)))
	finished := make(chan struct{})
	go func() { writer.run(stream); close(finished) }()
	remote, err := peer.AcceptUniStream(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte{0, 4, 0}, qpackBatchRead(t, remote, 3))
	remote.CancelRead(42)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the blocked control writer did not observe STOP_SENDING")
	}

	require.Zero(t, writer.pending.Load(), "empty and failed queued writes must both release pending ownership")
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), closed.ErrorCode)
}
