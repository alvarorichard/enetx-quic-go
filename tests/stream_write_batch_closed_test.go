package quic_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestStreamWriteBatchRejectsAnAlreadyClosedUniStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server := streamBatchConnectionPair(t, ctx, nil, nil)
	stream, err := client.OpenUniStream()
	require.NoError(t, err)
	n, err := stream.Write([]byte("delivered once"))
	require.Equal(t, len("delivered once"), n)
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	remote, err := server.AcceptUniStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.Equal(t, "delivered once", string(data))
	select {
	case <-stream.Context().Done():
	case <-ctx.Done():
		t.Fatal("the sender did not publish closure")
	}

	n, err = client.TryWriteStreamBatch([]quic.StreamWrite{{StreamID: stream.StreamID(), Data: []byte("never delivered")}})
	require.Zero(t, n)
	require.ErrorIs(t, err, quic.ErrStreamClosed)
	require.NoError(t, client.Context().Err(), "a stale stream ID must not close an otherwise healthy connection")
}
