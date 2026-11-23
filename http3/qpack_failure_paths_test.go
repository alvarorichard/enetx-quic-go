package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestStaticQPACKFailureClosesWithDecompressionCode(t *testing.T) {
	conn, _ := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	decoder := &streamFieldDecoder{conn: owner}
	// RFC 9204 Appendix A ends at index 98. This section requests index 99.
	_, err := decoder.Decode([]byte{0, 0, 0xff, 36})()
	require.Error(t, err)
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeQPACKDecompressionFailed), closed.ErrorCode)
}

func TestQPACKCancellationFailureClosesConnectionOnce(t *testing.T) {
	conn, _ := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	calls := 0
	owner.qpackDecoder = dynamic.NewDecoder(128, 1, func([]byte) error {
		calls++
		return errQPACKFeedbackBacklog
	})
	cancel := owner.qpackCancellation(0)
	cancel()
	cancel()
	require.Equal(t, 1, calls, "abandoning a section twice must not duplicate decoder feedback")
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeExcessiveLoad), closed.ErrorCode)
}

func TestQPACKCriticalStreamResetAndFeedbackOverload(t *testing.T) {
	for _, mode := range []string{"reset", "feedback-overload"} {
		t.Run(mode, func(t *testing.T) {
			conn, peer := newConnPair(t)
			owner := newRawConn(conn, false, nil, nil, nil, nil)
			owner.qpackDecoder = dynamic.NewDecoder(128, 1, func([]byte) error { return errQPACKFeedbackBacklog })
			sender, err := peer.OpenUniStream()
			require.NoError(t, err)
			data := []byte{0x20}
			if mode == "feedback-overload" {
				data = append(dynamic.AppendEncoderCapacity(nil, 128), 0x41, 'x', 1, 'y')
			}

			_, err = sender.Write(data)
			require.NoError(t, err)
			stream, err := conn.AcceptUniStream(t.Context())
			require.NoError(t, err)
			if mode == "reset" {
				sender.CancelWrite(42)
			} else {
				require.NoError(t, sender.Close())
			}

			owner.handleQPACKStream(stream, true)
			var closed *quic.ApplicationError
			require.ErrorAs(t, context.Cause(conn.Context()), &closed)
			want := ErrCodeClosedCriticalStream
			if mode == "feedback-overload" {
				want = ErrCodeExcessiveLoad
			}

			require.Equal(t, quic.ApplicationErrorCode(want), closed.ErrorCode)
		})
	}
}

func TestLegacyQPACKFeedbackWriteFailureClosesCriticalStream(t *testing.T) {
	conn, peer := newConnPair(t, withServerStreamWindow(32))
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	feedback := make(chan []byte, 2)
	feedback <- []byte{0x40}
	done := make(chan struct{})
	go func() {
		defer close(done)
		owner.writeQPACKFeedback(feedback)
	}()
	remote, err := peer.AcceptUniStream(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte{3, 0x40}, qpackBatchRead(t, remote, 2))
	remote.CancelRead(42)
	// Exceed remaining credit, so the write observes STOP_SENDING even if the
	// peer's cancellation and this enqueue race on the network.
	feedback <- bytes.Repeat([]byte{0x40}, 64)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("feedback writer did not stop after its critical stream was canceled")
	}

	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), closed.ErrorCode)
}

func TestQPACKSectionFeedbackFailureIsExcessiveLoad(t *testing.T) {
	conn, _ := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	overloaded := false
	owner.qpackDecoder = dynamic.NewDecoder(128, 1, func([]byte) error {
		if overloaded {
			return errQPACKFeedbackBacklog
		}

		return nil
	})
	data := append(dynamic.AppendEncoderCapacity(nil, 128), 0x41, 'x', 1, 'y')
	require.ErrorIs(t, owner.qpackDecoder.ReadEncoder(bytes.NewReader(data)), io.EOF)
	overloaded = true
	request, err := conn.OpenStream()
	require.NoError(t, err)
	tracked := owner.TrackStream(request)
	decoder := &streamFieldDecoder{conn: owner, context: t.Context(), stream: tracked, limit: 1024}
	_, err = decoder.Decode([]byte{2, 0, 0x80})()
	require.ErrorIs(t, err, errQPACKFeedbackBacklog)
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeExcessiveLoad), closed.ErrorCode)
}

func TestQPACKAdapterPropagatesQueueBackpressureWithoutDynamicReferences(t *testing.T) {
	conn, _ := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	qpack := newClientQPACK(owner, &QPACKConfig{
		DynamicTable: true, EncoderTableCapacity: 128,
		EncoderCapacityTiming: QPACKCapacityBeforeHeaders,
	}, make(chan struct{}), 1)
	qpack.encoder.reserved.Store(true)
	require.NoError(t, qpack.onSettings(128, 1, true))
	for range cap(qpack.encoder.queue) {
		require.NoError(t, qpack.encoder.enqueue([]byte{0x20}))
	}

	block, err := qpack.encode(0, []base.HeaderField{{Name: "x-first", Value: "retained"}})
	require.ErrorIs(t, err, errQPACKFeedbackBacklog)
	require.Nil(t, block)
	require.True(t, qpack.capacityPending, "capacity cannot be marked sent after queue rejection")
	<-qpack.encoder.queue
	block, err = qpack.encode(0, []base.HeaderField{{Name: "x-first", Value: "retained"}})
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0}, block[:2], "a rejected insertion must use a static field section")
	field, err := base.NewDecoder().Decode(block)()
	require.NoError(t, err)
	require.Equal(t, base.HeaderField{Name: "x-first", Value: "retained"}, field)

	require.Error(t, qpack.onSettings(64, 1, true), "a remembered nonzero capacity cannot shrink")
	owner.cancel(errors.New("test generation complete"))
}

func TestQPACKRequestPreparationDefersBusyControlStream(t *testing.T) {
	for _, mode := range []string{"initializing", "locked", "pending", "queue-full"} {
		t.Run(mode, func(t *testing.T) {
			client, _ := newQPACKBatchClient(t)
			request, err := client.conn.OpenStream()
			require.NoError(t, err)
			if mode == "initializing" {
				// A real initialization gate that has not yet published the encoder.
				client.rawConn.clientQPACK.encoder.ready = make(chan struct{})
				writer, release := client.prepareQPACKRequestHeaders(request)
				release()
				require.Same(t, request, writer)
				return
			}

			writer, release := client.prepareQPACKRequestHeaders(request)
			defer release()
			batch := writer.(*requestHeaderWriter).qpack
			if mode == "locked" {
				client.controlWriter.mu.Lock()
				defer client.controlWriter.mu.Unlock()
			} else if mode == "pending" {
				require.NoError(t, client.controlWriter.enqueue([]byte{33, 0}))
			} else {
				for range cap(client.controlWriter.queue) {
					require.NoError(t, client.controlWriter.enqueue([]byte{33, 0}))
				}
			}

			done, err := client.tryQPACKRequestBatch(batch, []byte{33, 0}, quic.StreamWrite{StreamID: request.StreamID()})
			require.False(t, done)
			if mode == "queue-full" {
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
			} else {
				require.ErrorIs(t, err, quic.ErrWouldBlock)
				require.Equal(t, []byte{33, 0}, (<-client.controlWriter.queue).data)
			}

			batch.release()
			require.True(t, batch.stream.writeMutex.TryLock(), "failed preparation must release the encoder writer")
			batch.stream.writeMutex.Unlock()
		})
	}
}
