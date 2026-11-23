package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/quicvarint"
	"github.com/enetx/quic-go/testutils/events"
	"github.com/stretchr/testify/require"
)

func TestBufferedControlSettingsRequiresCompleteBoundedPrelude(t *testing.T) {
	for _, data := range [][]byte{
		{0, 4, 0},
		{0, 4, 2, 1, 0},
		{0, 4},
		{0x40},
		{0, 0x40},
		{0, 4, 0x40},
		{0, 4, 3, 1},
		{2},
		{0, 33, 0},
		quicvarint.Append([]byte{0, 4}, 65537),
		// Three eight-byte varints are valid even for tiny values.
		{0xc0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 4, 0xc0, 0, 0, 0, 0, 0, 0, 0},
	} {
		t.Run(fmt.Sprintf("%x", data), func(t *testing.T) {
			conn, peer := newConnPair(t)
			out, err := peer.OpenUniStream()
			require.NoError(t, err)
			_, err = out.Write(data)
			require.NoError(t, err)
			in, err := conn.AcceptUniStream(t.Context())
			require.NoError(t, err)
			buffer := make([]byte, len(data))
			require.Eventually(t, func() bool { _, err := in.TryPeek(buffer); return err == nil }, time.Second, time.Millisecond)
			complete := bytes.Equal(data, []byte{0, 4, 0}) || len(data) == 5 || len(data) == 24
			require.Equal(t, complete, bufferedControlSettings(in))
			_, err = in.TryPeek(buffer)
			require.NoError(t, err)
			require.Equal(t, data, buffer, "probing must not consume stream bytes")
		})
	}
}

func TestClientBufferedSettingsPrecedeFirstRequestWithoutWaitingForMissingBytes(t *testing.T) {
	for _, restart := range []bool{false, true} {
		for _, buffered := range []bool{false, true} {
			t.Run(fmt.Sprintf("restart=%t/buffered=%t", restart, buffered), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				var recorder events.Recorder
				conn, peer := newConnPair(t, withClientRecorder(&recorder))
				control, err := peer.OpenUniStream()
				require.NoError(t, err)
				payload := quicvarint.Append(nil, 1)
				payload = quicvarint.Append(payload, 4096)
				payload = append(payload, 7, 16)
				settings := append(quicvarint.Append([]byte{0, 4}, uint64(len(payload))), payload...)
				prefix := settings
				if !buffered {
					prefix = settings[:1]
				}

				_, err = control.Write(prefix)
				require.NoError(t, err)
				// QUIC logs after handling frames: the chosen prefix is buffered
				// before the HTTP/3 transport and its reader goroutines exist.
				require.Eventually(t, func() bool {
					for _, event := range recorder.Events(transportlog.PacketReceived{}) {
						for _, frame := range event.(transportlog.PacketReceived).Frames {
							if sf, ok := frame.Frame.(*transportlog.StreamFrame); ok && sf.StreamID == control.StreamID() && sf.Offset+sf.Length >= int64(len(prefix)) {
								return true
							}
						}
					}
					return false
				}, time.Second, time.Millisecond)
				transport := &Transport{
					EarlyDataRestart: restart,
					QPACKConfig: &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096,
						StreamOrder: []QPACKStreamType{QPACKEncoderStream, QPACKDecoderStream}},
					Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) { return conn, nil },
				}
				require.NoError(t, transport.init())
				_, client, err := transport.dial(ctx, "localhost:443")
				require.NoError(t, err)
				native, ok := client.(*ClientConn)
				if !ok {
					native = client.(*earlyRestartClient).current.Load()
				}

				first := bufferedRequestSection(t, ctx, client, peer)
				require.Equal(t, buffered, first[0] != 0, "first request must use exactly the received peer limits")
				if !buffered {
					_, err = control.Write(settings[1:])
					require.NoError(t, err)
					select {
					case <-native.ReceivedSettings():
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}

					second := bufferedRequestSection(t, ctx, client, peer)
					require.NotZero(t, second[0], "late SETTINGS must enable dynamic encoding on the same connection")
				}
			})
		}
	}
}

func bufferedRequestSection(t *testing.T, ctx context.Context, client clientConn, peer *quic.Conn) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost/", nil)
	require.NoError(t, err)
	req.Header.Set("X-Cold", "first-request")
	done := make(chan error, 1)
	go func() {
		response, err := client.RoundTrip(req)
		if err == nil {
			_, err = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		done <- err
	}()
	request, err := peer.AcceptStream(ctx)
	require.NoError(t, err)
	require.NoError(t, request.SetReadDeadline(time.Now().Add(5*time.Second)))
	r := quicvarint.NewReader(request)
	typ, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.EqualValues(t, 1, typ)
	length, err := quicvarint.Read(r)
	require.NoError(t, err)
	require.Less(t, length, uint64(65536))
	block := make([]byte, length)
	_, err = io.ReadFull(request, block)
	require.NoError(t, err)
	_, err = request.Write([]byte{1, 3, 0, 0, 0xd9}) // Static :status 200; no dynamic response table.
	require.NoError(t, err)
	require.NoError(t, request.Close())
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return block
}

func TestBufferedInputRejectionRetainsUnopenedRequestBody(t *testing.T) {
	conn, _ := newConnPair(t)
	client := newClientConn(conn, false, nil, 0, false, nil)
	client.initialInputReady = make(chan struct{})
	client.rawConn.cancel(quic.Err0RTTRejected)
	req, err := http.NewRequestWithContext(t.Context(), "POST", "https://localhost/", strings.NewReader("unopened"))
	require.NoError(t, err)
	_, err = client.RoundTrip(req)
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	var unused *errConnUnusable
	require.ErrorAs(t, err, &unused, "rejection before stream admission must not reopen a body factory")
	remaining, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, "unopened", string(remaining))
}
