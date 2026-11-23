package http3

import (
	"context"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRequestAdmissionHonorsAnAlreadyCanceledContext(t *testing.T) {
	conn, _ := newConnPair(t, withServerBidiStreamLimit(-1))
	client := newClientConn(conn, false, nil, 0, false, nil)
	require.NoError(t, client.waitInitialSettings(t.Context()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	stream, err := client.OpenRequestStream(ctx)
	require.Nil(t, stream)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, client.rawConn.streams)
	require.NoError(t, context.Cause(conn.Context()))
}

func TestCanceledRequestDoesNotWaitForBufferedInitialInput(t *testing.T) {
	conn, _ := newConnPair(t)
	client := newClientConn(conn, false, nil, 0, false, nil)
	client.initialInputReady = make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
	require.NoError(t, err)
	response, err := client.RoundTrip(request)
	require.Nil(t, response)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, client.rawConn.streams)
}

func TestRetiredOwnerRejectsTrackingWithoutTakingStreamOwnership(t *testing.T) {
	conn, _ := newConnPair(t)
	client := newClientConn(conn, false, nil, 0, false, nil)
	require.NoError(t, client.waitInitialSettings(t.Context()))
	active, err := conn.OpenStream()
	require.NoError(t, err)
	require.NotNil(t, client.rawConn.trackStream(active, true))
	client.retire()
	str, err := conn.OpenStream()
	require.NoError(t, err)
	require.Nil(t, client.rawConn.trackStream(str, true))
	require.Len(t, client.rawConn.streams, 1)
	require.NoError(t, context.Cause(conn.Context()), "the existing stream retains the draining connection")
	str.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	str.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
}
