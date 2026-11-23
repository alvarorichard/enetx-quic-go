package quic_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRangeRecoverySupportsRepliesOnPeerInitiatedBidirectionalStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client, server := streamBatchConnectionPair(t, ctx, nil, &quic.Config{
		ClientHandshake: &quic.ClientHandshake{StreamDataRecovery: true},
	})
	outgoing, err := server.OpenStream()
	require.NoError(t, err)
	_, err = outgoing.Write([]byte("peer initiated request"))
	require.NoError(t, err)
	require.NoError(t, outgoing.Close())
	incoming, err := client.AcceptStream(ctx)
	require.NoError(t, err)
	data, err := io.ReadAll(incoming)
	require.NoError(t, err)
	require.Equal(t, "peer initiated request", string(data))
	reply := []byte("range tracked response on the incoming stream")
	_, err = incoming.Write(reply)
	require.NoError(t, err)
	require.NoError(t, incoming.Close())
	data, err = io.ReadAll(outgoing)
	require.NoError(t, err)
	require.Equal(t, reply, data)
	require.NoError(t, client.Context().Err())
}
