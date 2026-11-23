package http3

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestTruncatedStreamTypeIsLoggedWithoutClosingConnection(t *testing.T) {
	conn, peer := newConnPair(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	owner := newRawConn(conn, false, nil, nil, nil, logger)
	stream, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write([]byte{0x40})
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	in, err := conn.AcceptUniStream(t.Context())
	require.NoError(t, err)
	owner.handleUnidirectionalStream(in, false)
	require.Contains(t, logs.String(), "reading stream type on stream failed")
	require.NoError(t, conn.Context().Err())
}

type connectionLogSink chan string

func (s connectionLogSink) Write(data []byte) (int, error) {
	s <- string(data)
	return len(data), nil
}

func TestDatagramReceiverLogsShutdownAndPreservesThePeerCause(t *testing.T) {
	conn, peer := newConnPair(t, withDatagrams())
	logs := make(connectionLogSink, 16)
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	owner := newRawConn(conn, true, nil, nopControlStrHandler, nil, logger)
	stream, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write((&settingsFrame{Datagram: true, MaxFieldSectionSize: -1}).Append([]byte{0}))
	require.NoError(t, err)
	in, err := conn.AcceptUniStream(t.Context())
	require.NoError(t, err)
	go owner.handleUnidirectionalStream(in, false)
	select {
	case <-owner.ReceivedSettings():
	case <-time.After(5 * time.Second):
		t.Fatal("the datagram receiver did not accept peer settings")
	}

	require.NoError(t, peer.CloseWithError(77, "peer shutdown"))
	timeout := time.After(5 * time.Second)
	for {
		select {
		case line := <-logs:
			if strings.Contains(line, "receiving datagrams failed") {
				require.Contains(t, line, "peer shutdown")
				// The datagram queue closes before Conn.run publishes its context
				// cause. The diagnostic alone does not synchronize that publication.
				select {
				case <-conn.Context().Done():
				case <-timeout:
					t.Fatal("the connection did not publish its shutdown cause")
				}

				var closed *quic.ApplicationError
				require.ErrorAs(t, context.Cause(conn.Context()), &closed)
				require.EqualValues(t, 77, closed.ErrorCode)
				require.Equal(t, "peer shutdown", closed.ErrorMessage)
				require.True(t, closed.Remote)
				return
			}
		case <-timeout:
			t.Fatal("the stopped datagram receiver did not publish its diagnostic")
		}
	}
}

func TestPeerSettingsCannotShrinkAlreadyRestoredQPACKLimits(t *testing.T) {
	conn, peer := newConnPair(t)
	owner := newRawConn(conn, false, nil, nil, nil, nil)
	owner.clientQPACK = newClientQPACK(owner, &QPACKConfig{
		DynamicTable: true, EncoderTableCapacity: 128, EncoderCapacityTiming: QPACKCapacityBeforeHeaders,
	}, make(chan struct{}), 32)
	require.NoError(t, owner.clientQPACK.onSettings(128, 1, true))
	stream, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = stream.Write((&settingsFrame{
		MaxFieldSectionSize: -1, Other: orderedTestSettings(map[uint64]uint64{1: 64, 7: 1}),
	}).Append([]byte{0}))
	require.NoError(t, err)
	in, err := conn.AcceptUniStream(t.Context())
	require.NoError(t, err)
	owner.handleUnidirectionalStream(in, false)
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeExcessiveLoad), closed.ErrorCode)
}

func TestServerRejectsMalformedStaticQPACKBeforeCallingTheHandler(t *testing.T) {
	conn, peer := newConnPair(t)
	server := &Server{Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a malformed field section reached the request handler")
	})}
	server.init()
	defer server.Close()
	go server.handleConn(peer)
	stream, err := conn.OpenStream()
	require.NoError(t, err)
	// Static index 99 is outside RFC 9204 Appendix A's 0..98 table.
	_, err = stream.Write([]byte{1, 4, 0, 0, 0xff, 36})
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = stream.Read(make([]byte, 1))
	var reset *quic.StreamError
	require.ErrorAs(t, err, &reset)
	require.Equal(t, quic.StreamErrorCode(ErrCodeQPACKDecompressionFailed), reset.ErrorCode)
	require.NoError(t, conn.Context().Err())
}
