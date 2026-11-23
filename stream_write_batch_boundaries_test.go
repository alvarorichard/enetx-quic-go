package quic

import (
	"context"
	"errors"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestStreamBatchCountsDataAcceptedBeforeConcurrentFINCancellation(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	streams := newStreamsMap(t.Context(), sender, func(wire.Frame) {}, func(id protocol.StreamID) *streamFlowController {
		return newTestStreamFlowControllerWithSendWindow(id, 1024)
	}, 0, 0, false, protocol.PerspectiveClient)
	streams.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeBidi, MaxStreamNum: 1})
	stream, err := streams.OpenStream()
	require.NoError(t, err)
	sender.EXPECT().onHasStreamData(stream.StreamID(), stream.sendStr).Do(func(_ protocol.StreamID, sending *SendStream) {
		// A writer can cancel between publication of accepted data and FIN.
		sending.CancelWrite(42)
	})
	sender.EXPECT().onHasStreamControlFrame(stream.StreamID(), stream).Times(1)
	conn := &Conn{streamsMap: streams}
	batch := streamWriteBatch{
		writes: []StreamWrite{{StreamID: stream.StreamID(), Data: []byte("accepted prefix"), Fin: true}},
		done:   make(chan streamWriteResult, 1),
	}
	conn.writeStreamBatch(batch)
	result := <-batch.done
	require.Equal(t, 1, result.count, "already accepted elements cannot be replayed after a FIN failure")
	require.ErrorContains(t, result.err, "close called for canceled stream")
	var canceled *StreamError
	require.ErrorAs(t, context.Cause(stream.Context()), &canceled)
	require.EqualValues(t, 42, canceled.ErrorCode)
}

func TestStreamBatchCancellationPreservesPublishedResult(t *testing.T) {
	for _, stage := range []string{"before-admission", "waiting-result", "published-result"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("connection closed during stream admission")
			conn := &Conn{ctx: ctx, perspective: protocol.PerspectiveClient, streamWriteBatches: make(chan streamWriteBatch)}
			if stage == "before-admission" {
				cancel(cause)
				count, err := conn.TryWriteStreamBatch([]StreamWrite{{StreamID: 0, Data: []byte("not accepted")}})
				require.Zero(t, count)
				require.ErrorIs(t, err, cause)
				return
			}

			done := make(chan streamWriteResult, 1)
			go func() {
				count, err := conn.TryWriteStreamBatch([]StreamWrite{{StreamID: 0, Data: []byte("prefix")}})
				done <- streamWriteResult{count: count, err: err}
			}()
			batch := <-conn.streamWriteBatches
			if stage == "published-result" {
				batch.done <- streamWriteResult{count: 1}
			}

			cancel(cause)
			result := <-done
			if stage == "published-result" {
				require.Equal(t, 1, result.count)
				require.NoError(t, result.err, "shutdown must not discard an accepted result")
			} else {
				require.Zero(t, result.count)
				require.ErrorIs(t, result.err, cause)
			}
		})
	}
}

func TestStreamBatchRejectsStreamRemovedByItsFinalACK(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	streams := newStreamsMap(t.Context(), sender, func(wire.Frame) {}, func(id protocol.StreamID) *streamFlowController {
		return newTestStreamFlowControllerWithSendWindow(id, 1024)
	}, 0, 0, false, protocol.PerspectiveClient)
	streams.HandleMaxStreamsFrame(&wire.MaxStreamsFrame{Type: protocol.StreamTypeUni, MaxStreamNum: 1})
	stream, err := streams.OpenUniStream()
	require.NoError(t, err)
	sender.EXPECT().onHasStreamData(stream.StreamID(), stream).Times(2)
	require.NoError(t, stream.TryWriteAll([]byte("acknowledged")))
	require.NoError(t, stream.Close())
	frame, _, _ := stream.popStreamFrame(1200, protocol.Version1)
	require.NotNil(t, frame.Frame)
	require.True(t, frame.Frame.Fin)
	sender.EXPECT().onStreamCompleted(stream.StreamID()).Do(func(id protocol.StreamID) {
		require.NoError(t, streams.DeleteStream(id))
	})
	frame.Handler.OnAcked(frame.Frame)
	batch := streamWriteBatch{
		writes: []StreamWrite{{StreamID: stream.StreamID(), Data: []byte("must not be sent")}},
		done:   make(chan streamWriteResult, 1),
	}
	(&Conn{streamsMap: streams}).writeStreamBatch(batch)
	result := <-batch.done
	require.Zero(t, result.count)
	require.ErrorIs(t, result.err, ErrStreamClosed)
}

func TestStreamBatchWaitPreservesPublishedAcceptanceWhenShutdownIsAlreadyReady(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("connection closed after admission completed")
	cancel(cause)
	for _, result := range []streamWriteResult{{count: 1}, {count: 1, err: ErrWouldBlock}} {
		for range 64 {
			batch := streamWriteBatch{done: make(chan streamWriteResult, 1)}
			batch.done <- result
			count, err := batch.wait(ctx)
			require.Equal(t, 1, count, "a concurrent close must not make accepted bytes replayable")
			require.ErrorIs(t, err, result.err)
		}
	}

	batch := streamWriteBatch{done: make(chan streamWriteResult, 1)}
	count, err := batch.wait(ctx)
	require.Zero(t, count)
	require.ErrorIs(t, err, cause, "an unpublished admission retains the connection's shutdown cause")
}
