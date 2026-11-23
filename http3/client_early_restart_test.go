package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestRetiredEarlyGenerationUnblocksExtendedConnect(t *testing.T) {
	conn, _ := newConnPair(t)
	client := (&Transport{}).NewClientConn(conn)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "https://example.com", nil)
	require.NoError(t, err)
	request.Proto = "websocket"
	finished := make(chan error, 1)
	go func() { _, err := client.RoundTrip(request); finished <- err }()
	client.rawConn.retireEarlyData()
	select {
	case err := <-finished:
		require.ErrorIs(t, err, quic.Err0RTTRejected)
		var unopened *errConnUnusable
		require.True(t, errors.As(err, &unopened))
	case <-time.After(time.Second):
		t.Fatal("request kept waiting for retired SETTINGS")
	}
	// Protocol workers finishing late must not close the replacement connection.
	require.NoError(t, client.rawConn.CloseWithError(quic.ApplicationErrorCode(ErrCodeInternalError), "retired worker"))
	require.NoError(t, context.Cause(conn.Context()))
}

func TestEarlyRestartReadyIsOneShot(t *testing.T) {
	conn, _ := newConnPair(t)
	old := (&Transport{}).NewClientConn(conn)
	created := 0
	fresh := &ClientConn{}
	client := newEarlyRestartClient(old, func() *ClientConn { created++; return fresh })
	client.applicationReady() // Normal handshakes must retain their original state.
	require.Zero(t, created)
	client.reject()
	client.applicationReady()
	client.applicationReady()
	require.Equal(t, 1, created)
	active, err := client.active(t.Context())
	require.NoError(t, err)
	require.Same(t, fresh, active)
}

func TestLocalRejectionErrorCannotCreateANewEarlyGeneration(t *testing.T) {
	conn, _ := newConnPair(t)
	calls := 0
	original := (&Transport{WireConfig: &WireConfig{
		RequestGreaseFrames: func(*http.Request) ([]GreaseFrame, error) {
			calls++
			return nil, quic.Err0RTTRejected
		},
	}}).NewClientConn(conn)
	client := newEarlyRestartClient(original, func() *ClientConn {
		t.Fatal("an application callback cannot trigger QUIC generation replacement")
		return nil
	})
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	require.NoError(t, err)
	response, err := client.RoundTrip(request)
	require.Nil(t, response)
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	var preparation *RequestPreparationError
	require.ErrorAs(t, err, &preparation)
	require.Equal(t, 1, calls)
	require.False(t, client.rejected.Load())
	require.NoError(t, context.Cause(conn.Context()))
}

func TestEarlyRestartWaitHonorsRequestAndConnectionCancellation(t *testing.T) {
	for _, mode := range []string{"request", "connection"} {
		t.Run(mode, func(t *testing.T) {
			conn, _ := newConnPair(t)
			original := (&Transport{}).NewClientConn(conn)
			client := newEarlyRestartClient(original, func() *ClientConn {
				t.Fatal("a canceled wait must not create a replacement")
				return nil
			})
			client.reject()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			var cause error
			if mode == "request" {
				cause = errors.New("request abandoned during early rejection")
				cancel(cause)
			} else {
				require.NoError(t, conn.CloseWithError(123, "connection abandoned during early rejection"))
				cause = context.Cause(conn.Context())
			}

			request, err := http.NewRequestWithContext(ctx, MethodGet0RTT, "https://localhost/", nil)
			require.NoError(t, err)
			response, err := client.RoundTrip(request)
			require.Nil(t, response)
			require.ErrorIs(t, err, cause)
			stream, err := client.OpenRequestStream(ctx)
			require.Nil(t, stream)
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestEarlyRestartForwardsOpenRequestStream(t *testing.T) {
	conn, peer := newConnPair(t)
	original := (&Transport{}).NewClientConn(conn)
	client := newEarlyRestartClient(original, nil)
	stream, err := client.OpenRequestStream(t.Context())
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodHead, "https://localhost/", nil)
	require.NoError(t, err)
	require.NoError(t, stream.SendRequestHeader(req))
	require.NoError(t, stream.Close())
	remote, err := peer.AcceptStream(t.Context())
	require.NoError(t, err)
	data, err := io.ReadAll(remote)
	require.NoError(t, err)
	require.NotEmpty(t, data)
	require.True(t, bytes.HasPrefix(data, []byte{1}), "the forwarded stream sends a HEADERS frame")
}
