package http3

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQPACKPendingWriteStopsWhenPeerCancelsStream(t *testing.T) {
	conn, peer := newConnPair(t, withServerStreamWindow(32))
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	qpack := newClientQPACK(owner, &QPACKConfig{}, make(chan struct{}), 1)
	done := make(chan error, 1)
	go func() {
		qpack.encoder.writeMutex.Lock()
		defer qpack.encoder.writeMutex.Unlock()
		done <- qpack.encoder.write(bytes.Repeat([]byte{0x20}, 64<<10))
	}()
	remote, err := peer.AcceptUniStream(t.Context())
	require.NoError(t, err)
	require.Equal(t, []byte{2}, qpackBatchRead(t, remote, 1))
	remote.CancelRead(42)
	select {
	case err := <-done:
		require.Error(t, err, "the blocked write cannot succeed after STOP_SENDING")
	case <-time.After(5 * time.Second):
		t.Fatal("QPACK writer stayed blocked after cancellation")
	}

	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("canceling the encoder stream did not close its connection")
	}

	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeClosedCriticalStream), closed.ErrorCode)
}

func TestQPACKSetupPreservesConnectionShutdownCause(t *testing.T) {
	for _, eager := range []bool{false, true} {
		conn, _ := newConnPair(t)
		owner := newRawConn(conn, false, nil, nil, nil, nil)
		qpack := newClientQPACK(owner, &QPACKConfig{
			StreamOrder: []QPACKStreamType{QPACKEncoderStream, QPACKDecoderStream}, EagerStreamTypes: eager,
		}, make(chan struct{}), 1)
		if eager {
			require.NoError(t, qpack.prepare())
		}

		require.NoError(t, conn.CloseWithError(77, "shutdown during critical stream initialization"))
		if eager {
			require.ErrorIs(t, qpack.stageEagerTypes(), context.Cause(conn.Context()))
		} else {
			require.ErrorIs(t, qpack.prepare(), context.Cause(conn.Context()))
		}
	}
}

func TestManualClientConnectionValidatesQPACKConfiguration(t *testing.T) {
	conn, _ := newConnPair(t)
	client := (&Transport{QPACKConfig: &QPACKConfig{Huffman: 255}}).NewClientConn(conn)
	stream, err := client.OpenRequestStream(t.Context())
	require.Nil(t, stream)
	require.ErrorContains(t, err, "invalid QPACK encoder options")
}

func TestEagerQPACKTypesResumeAfterInitialControlExhaustsConnectionCredit(t *testing.T) {
	// A minimal control prelude uses exactly three bytes. Its successful write
	// can consume all connection credit before the fresh QPACK type bytes fit.
	conn, peer := newConnPair(t, withServerConnectionWindow(3))
	client := (&Transport{
		WireConfig: &WireConfig{CoalesceInitialSettings: true},
		QPACKConfig: &QPACKConfig{
			StreamOrder: []QPACKStreamType{QPACKEncoderStream, QPACKDecoderStream}, EagerStreamTypes: true,
		},
	}).NewClientConn(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, client.waitInitialSettings(ctx), "eager types must not delay initialization while connection credit is exhausted")
	control, err := peer.AcceptUniStream(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 4, 0}, qpackBatchRead(t, control, 3))
	for _, expected := range []byte{2, 3} {
		stream, err := peer.AcceptUniStream(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
		require.Equal(t, []byte{expected}, qpackBatchRead(t, stream, 1), "returning connection credit must resume each original critical stream")
	}

	require.NoError(t, conn.Context().Err())
}
