package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestPreconnectCancellationRacingWithItsReportedStartPreservesCause(t *testing.T) {
	for range 64 {
		ctx, cancel := context.WithCancelCause(t.Context())
		cause := errors.New("application canceled while connection start was being reported")
		transport := &Transport{Dial: func(shared context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			NotifyConnectionStarted(shared)
			cancel(cause)
			return nil, cause
		}}
		calls := 0
		conn, err := transport.PreconnectWithOptions(ctx, "localhost:443", PreconnectOptions{
			OnConnectionStarted: func() { calls++ },
		})
		require.Nil(t, conn)
		require.ErrorIs(t, err, cause)
		require.LessOrEqual(t, calls, 1, "a start observed before cancellation is delivered at most once")
		require.NoError(t, transport.Close())
		cancel(nil)
	}
}

func TestCancellationDuringFinalReusePolicyPassCannotStartADedicatedDial(t *testing.T) {
	transport, port, dials := reuseTestTransport(t)
	reuseRequest(t, transport, "localhost:"+port, true)
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	cause := errors.New("request canceled during final cross-origin route authorization")
	var passes []bool
	transport.ConnectionReusePolicy = func(_ context.Context, info ConnectionReuseInfo) bool {
		passes = append(passes, info.AllowNetwork)
		if info.AllowNetwork {
			cancel(cause)
		}

		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:"+port, nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.Nil(t, response)
	require.ErrorIs(t, err, cause)
	require.Equal(t, []bool{false, true}, passes)
	require.EqualValues(t, 1, dials.Load(), "cancellation cannot escape the cache lookup by falling back to a fresh dial")
}

func TestRepeatedRetirementRetainsOneOwnerUntilActiveResponseFinishes(t *testing.T) {
	transport, port, _ := reuseTestTransport(t)
	address := "localhost:" + port
	response := reuseRequest(t, transport, address, false)
	defer response.Body.Close()
	old := transport.clients[address]
	transport.mutex.Lock()
	transport.retireClientLocked(old)
	transport.retireClientLocked(old)
	owners := len(transport.retired)
	transport.mutex.Unlock()
	require.Equal(t, 1, owners, "concurrent failed attempts can retire the same shared connection")
	require.False(t, transport.HasCachedConnection(t.Context(), address))
	require.NoError(t, old.conn.Context().Err())
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, address, string(body))
	require.NoError(t, response.Body.Close())
	transport.CloseIdleConnections()
	require.Error(t, old.conn.Context().Err())
	transport.mutex.Lock()
	remaining := len(transport.retired)
	transport.mutex.Unlock()
	require.Zero(t, remaining)
}
