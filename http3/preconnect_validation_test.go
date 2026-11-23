package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

func TestPreconnectRejectsInvalidConfigurationAndClosedTransportBeforeDial(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-config", true: "closed"}[closed], func(t *testing.T) {
			var dials, notifications atomic.Int32
			transport := &Transport{Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
				dials.Add(1)
				return nil, errors.New("unexpected network access")
			}}
			defer transport.Close()
			if closed {
				require.NoError(t, transport.Close())
			} else {
				transport.QPACKConfig = &QPACKConfig{EncoderCapacityTiming: 255}
			}

			conn, err := transport.PreconnectWithOptions(t.Context(), "localhost:443", PreconnectOptions{
				OnConnectionStarted: func() { notifications.Add(1) },
			})
			require.Nil(t, conn)
			if closed {
				require.ErrorIs(t, err, ErrTransportClosed)
			} else {
				require.ErrorContains(t, err, "capacity timing")
			}

			require.Zero(t, dials.Load())
			require.Zero(t, notifications.Load())
		})
	}
}

func TestPreconnectDialFailurePreservesCauseAndDropsFailedPoolEntry(t *testing.T) {
	sentinel := errors.New("QUIC connection attempt failed")
	var calls atomic.Int32
	transport := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		calls.Add(1)
		NotifyConnectionStarted(ctx)
		return nil, sentinel
	}}
	defer transport.Close()
	for range 3 {
		notifications := 0
		conn, err := transport.PreconnectWithOptions(t.Context(), "localhost:443", PreconnectOptions{
			OnConnectionStarted: func() { notifications++ },
		})
		require.ErrorIs(t, err, sentinel)
		require.Nil(t, conn)
		require.Equal(t, 1, notifications, "a completed failed attempt still reports its actual start exactly once")
		transport.mutex.Lock()
		remaining := len(transport.clients)
		transport.mutex.Unlock()
		require.Zero(t, remaining, "a failed dial must not poison the next preparation")
	}

	require.EqualValues(t, 3, calls.Load())
}

func TestPreconnectCancellationFromStartCallbackDoesNotPublishConnection(t *testing.T) {
	for _, closeConnection := range []bool{false, true} {
		conn, _ := newConnPair(t)
		transport := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			NotifyConnectionStarted(ctx)
			return conn, nil
		}}
		ctx, cancel := context.WithCancelCause(t.Context())
		cause := errors.New("preparation abandoned from connection start callback")
		calls := 0
		got, err := transport.PreconnectWithOptions(ctx, "localhost:443", PreconnectOptions{
			Early: true,
			OnConnectionStarted: func() {
				calls++
				if closeConnection {
					require.NoError(t, conn.CloseWithError(77, "preparation stopped"))
				} else {
					cancel(cause)
				}
			},
		})
		require.Nil(t, got)
		if closeConnection {
			require.ErrorIs(t, err, context.Cause(conn.Context()))
		} else {
			require.ErrorIs(t, err, cause)
		}

		require.Equal(t, 1, calls)
		require.NoError(t, transport.Close())
		cancel(nil)
	}
}

func TestConcurrentCallerObservesCompletedDialFailure(t *testing.T) {
	cause := errors.New("shared dial failed before its next waiter joined")
	gate := make(chan struct{})
	transport := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}

		return nil, cause
	}}
	defer transport.Close()
	require.NoError(t, transport.init())
	first, _, err := transport.getClient(t.Context(), "localhost:443", false)
	require.NoError(t, err)
	close(gate)
	<-first.dialing
	defer func() { first.useCount.Add(-1); first.Close() }()
	second, _, err := transport.getClient(t.Context(), "localhost:443", false)
	require.ErrorIs(t, err, cause)
	require.Nil(t, second)
	require.Empty(t, transport.clients)
}

func TestPreconnectImmediateDialFailureAlwaysReportsItsStart(t *testing.T) {
	cause := errors.New("dial failed immediately after reporting its start")
	transport := &Transport{Dial: func(ctx context.Context, _ string, _ *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		NotifyConnectionStarted(ctx)
		return nil, cause
	}}
	defer transport.Close()
	for attempt := range 1000 {
		calls := 0
		conn, err := transport.PreconnectWithOptions(t.Context(), "localhost:443", PreconnectOptions{
			OnConnectionStarted: func() { calls++ },
		})
		require.Nil(t, conn)
		require.ErrorIs(t, err, cause)
		require.Equal(t, 1, calls, "attempt %d lost its already-reported connection start", attempt)
	}
}
