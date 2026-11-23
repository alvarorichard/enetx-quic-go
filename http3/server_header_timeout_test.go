package http3

import (
	"bytes"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-g"
	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-http/httptest"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/alvarorichard/enetx-quic-go/quicvarint"
	"github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func requestHeaderTimeoutSettings() g.MapOrd[uint64, uint64] {
	settings := g.NewMapOrd[uint64, uint64]()
	settings.Insert(1, 64)
	settings.Insert(7, 1)
	return settings
}

func requestHeaderTimeoutBlock(t *testing.T) []byte {
	t.Helper()
	var buffer bytes.Buffer
	encoder := qpack.NewEncoder(&buffer)
	for _, field := range []qpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
	} {
		require.NoError(t, encoder.WriteField(field))
	}

	require.NoError(t, encoder.Close())
	block := buffer.Bytes()
	require.GreaterOrEqual(t, len(block), 2)
	block[0], block[1] = 2, 0   // Required Insert Count 1, Base 1.
	block = append(block, 0x80) // Dynamic relative index 0.
	frame := quicvarint.Append(nil, 1)
	frame = quicvarint.Append(frame, uint64(len(block)))
	return append(frame, block...)
}

func TestServerReadHeaderTimeoutBoundsBlockedQPACK(t *testing.T) {
	client, peer := newConnPair(t)
	var handled atomic.Int32
	server := &Server{
		ReadHeaderTimeout:  scaleDuration(30 * time.Millisecond),
		AdditionalSettings: requestHeaderTimeoutSettings(),
		Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			handled.Add(1)
		}),
	}
	defer server.Close()
	go server.ServeQUICConn(peer)

	control, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0})
	require.NoError(t, err)

	encoder, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = encoder.Write([]byte{2, 0x3f, 33}) // Encoder type, capacity 64.
	require.NoError(t, err)

	stream, err := client.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write(requestHeaderTimeoutBlock(t))
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(scaleDuration(time.Second))))
	_, err = stream.Read(make([]byte, 1))
	var streamError *quic.StreamError
	require.ErrorAs(t, err, &streamError)
	require.True(t, streamError.Remote)
	require.EqualValues(t, ErrCodeRequestIncomplete, streamError.ErrorCode)
	require.Zero(t, handled.Load())
	require.NoError(t, client.Context().Err())

	// A request-local timeout must preserve the connection and decoder budget.
	next, err := client.OpenStream()
	require.NoError(t, err)
	_, err = next.Write(encodeRequest(t, httptest.NewRequest(http.MethodGet, "https://example.com", nil)))
	require.NoError(t, err)
	require.NoError(t, next.Close())
	require.Equal(t, []string{"200"}, decodeHeader(t, next)[":status"])
	require.EqualValues(t, 1, handled.Load())
}

func TestServerReadHeaderTimeoutDisabledWhileQPACKBlocked(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			client, peer := newConnPair(t)
			observed := make(chan string, 1)
			server := &Server{ReadHeaderTimeout: timeout,
				AdditionalSettings: requestHeaderTimeoutSettings(),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					observed <- r.Header.Get("x-test")
				}),
			}
			defer server.Close()
			go server.ServeQUICConn(peer)

			control, err := client.OpenUniStream()
			require.NoError(t, err)
			_, err = control.Write([]byte{0, 4, 0})
			require.NoError(t, err)
			encoder, err := client.OpenUniStream()
			require.NoError(t, err)
			_, err = encoder.Write([]byte{2, 0x3f, 33})
			require.NoError(t, err)

			stream, err := client.OpenStream()
			require.NoError(t, err)
			_, err = stream.Write(requestHeaderTimeoutBlock(t))
			require.NoError(t, err)
			require.NoError(t, stream.Close())
			require.NoError(t, stream.SetReadDeadline(time.Now().Add(scaleDuration(60*time.Millisecond))))
			_, err = stream.Read(make([]byte, 1))
			require.ErrorIs(t, err, os.ErrDeadlineExceeded)
			require.NoError(t, client.Context().Err())

			// Insert x-test: value and unblock the original valid request.
			_, err = encoder.Write(append([]byte{0x46}, []byte("x-test\x05value")...))
			require.NoError(t, err)
			require.NoError(t, stream.SetReadDeadline(time.Now().Add(scaleDuration(time.Second))))
			require.Equal(t, []string{"200"}, decodeHeader(t, stream)[":status"])
			require.Equal(t, "value", <-observed)
		})
	}
}

func TestServerReadHeaderTimeoutPreservesDynamicTrailers(t *testing.T) {
	client, peer := newConnPair(t)
	started := make(chan struct{})
	type result struct {
		body, trailer string
		err           error
	}
	observed := make(chan result, 1)
	server := &Server{
		ReadHeaderTimeout:  scaleDuration(30 * time.Millisecond),
		AdditionalSettings: requestHeaderTimeoutSettings(),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			body, err := io.ReadAll(r.Body)
			observed <- result{string(body), r.Trailer.Get("x-test"), err}
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
			}
		}),
	}
	defer server.Close()
	go server.ServeQUICConn(peer)

	control, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0})
	require.NoError(t, err)
	encoderStream, err := client.OpenUniStream()
	require.NoError(t, err)
	_, err = encoderStream.Write([]byte{2, 0x3f, 33})
	require.NoError(t, err)

	var block bytes.Buffer
	encoder := qpack.NewEncoder(&block)
	for _, field := range []qpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/"},
		{Name: "content-length", Value: "1"},
		{Name: "trailer", Value: "x-test"},
	} {
		require.NoError(t, encoder.WriteField(field))
	}

	require.NoError(t, encoder.Close())
	header := quicvarint.Append(nil, 1)
	header = quicvarint.Append(header, uint64(block.Len()))
	header = append(header, block.Bytes()...)
	stream, err := client.OpenStream()
	require.NoError(t, err)
	_, err = stream.Write(header)
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(scaleDuration(time.Second)):
		t.Fatal("request headers did not reach the handler")
	}

	// Wait beyond the header limit while the server reads the unfinished body.
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(2*server.ReadHeaderTimeout)))
	_, err = stream.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)
	require.NoError(t, client.Context().Err())
	require.NoError(t, stream.SetReadDeadline(time.Now().Add(scaleDuration(time.Second))))
	_, err = stream.Write([]byte{0, 1, 'x', 1, 3, 2, 0, 0x80}) // DATA then dynamic trailing HEADERS.
	require.NoError(t, err)
	require.NoError(t, stream.Close())
	_, err = encoderStream.Write(append([]byte{0x46}, []byte("x-test\x05value")...))
	require.NoError(t, err)
	require.Equal(t, []string{"200"}, decodeHeader(t, stream)[":status"])
	actual := <-observed
	require.NoError(t, actual.err)
	require.Equal(t, "x", actual.body)
	require.Equal(t, "value", actual.trailer)
}
