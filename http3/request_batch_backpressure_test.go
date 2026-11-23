package http3

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
)

type requestBatchWireWriter struct {
	*quic.Stream
	writes int
}

func (w *requestBatchWireWriter) Write(data []byte) (int, error) {
	w.writes++
	return w.Stream.Write(data)
}

func TestRequestBatchBackpressurePreservesHeadersAndControlOrder(t *testing.T) {
	for _, scenario := range []string{"request-credit", "queued-priority", "full-control-queue"} {
		t.Run(scenario, func(t *testing.T) {
			client, peer := newQPACKBatchClient(t, withServerStreamWindow(32))
			stream, err := client.conn.OpenStream()
			require.NoError(t, err)
			writer := &requestBatchWireWriter{Stream: stream}
			request, err := http.NewRequest(http.MethodGet, "https://localhost/", nil)
			require.NoError(t, err)
			if scenario != "request-credit" {
				client.wireConfig.SendPriorityUpdates = true
				request.Header.Set("Priority", "u=0")
				control, err := client.conn.OpenUniStream()
				require.NoError(t, err)
				client.controlWriter.attachStream(control)
				count := 1
				if scenario == "full-control-queue" {
					count = cap(client.controlWriter.queue)
				}

				for range count {
					require.NoError(t, client.controlWriter.enqueue([]byte{33, 0}))
				}
			}

			data := bytes.Repeat([]byte{1, 0}, 32)
			err = client.writeRequestHeaders(writer, request, stream.StreamID(), data)
			if scenario == "full-control-queue" {
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
				require.ErrorContains(t, err, "queue is full")
				require.Zero(t, writer.writes, "failed preparation cannot publish request bytes")
				return
			}

			require.NoError(t, err)
			require.Equal(t, 1, writer.writes, "the blocking fallback writes the unaccepted header exactly once")
			require.NoError(t, stream.Close())
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			remote, err := peer.AcceptStream(ctx)
			require.NoError(t, err)
			require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
			got, err := io.ReadAll(remote)
			require.NoError(t, err)
			require.Equal(t, data, got)
			if scenario == "queued-priority" {
				require.Equal(t, []byte{33, 0}, (<-client.controlWriter.queue).data)
				require.Equal(t, client.priorityUpdateFrame(stream.StreamID(), 0, false), (<-client.controlWriter.queue).data)
				require.Empty(t, client.controlWriter.queue)
			}
		})
	}
}
