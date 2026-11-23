package http3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type requestHeaderResultWriter struct {
	count int
	err   error
	calls int
	data  []byte
}

func (w *requestHeaderResultWriter) Write(data []byte) (int, error) {
	w.calls++
	w.data = bytes.Clone(data)
	return w.count, w.err
}

func TestRequestHeaderFallbackPreservesWriteOutcome(t *testing.T) {
	cause := errors.New("request stream write failed")
	for _, test := range []struct {
		name  string
		count int
		err   error
		want  error
	}{
		{name: "complete", count: 7},
		{name: "short", count: 3, want: io.ErrShortWrite},
		{name: "failure", count: 3, err: cause, want: cause},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := &requestHeaderResultWriter{count: test.count, err: test.err}
			err := writeRequestHeaderFallback(writer, []byte("headers"))
			require.ErrorIs(t, err, test.want)
			require.Equal(t, []byte("headers"), writer.data)
			require.Equal(t, 1, writer.calls, "the fallback must never replay a partial write")
		})
	}
}

func TestInitialSettingsWaitPreservesCancellationCause(t *testing.T) {
	require.NoError(t, new(ClientConn).waitInitialSettings(t.Context()))
	conn, _ := newConnPair(t)
	client := &ClientConn{conn: conn, initialSettingsWritten: make(chan struct{})}
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("request canceled before SETTINGS")
	cancel(cause)
	require.ErrorIs(t, client.waitInitialSettings(ctx), cause)
	require.NoError(t, context.Cause(conn.Context()), "a canceled request must not close the shared connection")
}

func TestResponseProgressErrorRetainsCause(t *testing.T) {
	cause := errors.New("response headers received before stream failure")
	err := &responseReceivedError{err: cause}
	require.Equal(t, cause.Error(), err.Error())
	require.ErrorIs(t, err, cause)
}

func TestReservedSettingsWithNoApplicationSettings(t *testing.T) {
	settings, err := connectionSettingsGrease(nil, func() (uint64, uint64, error) { return 33, 17, nil })
	require.NoError(t, err)
	require.Equal(t, uint64(17), settings.Get(33).Unwrap())
	require.EqualValues(t, 1, settings.Len())
}
