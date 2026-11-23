package http3

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/enetx/http"
	"github.com/enetx/http/headerorder"
	"github.com/enetx/http/httptrace"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/http3/qlog"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	"github.com/enetx/quic-go/testutils/events"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestDynamicTrailersValidateBeforeEncodingAndPreserveWireOrder(t *testing.T) {
	for _, mode := range []string{"valid", "invalid-name", "invalid-value", "filtered", "encoder-error", "write-error"} {
		t.Run(mode, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, "https://localhost/", nil)
			require.NoError(t, err)
			request.Trailer = http.Header{
				"X-Last": {"last"}, "X-First": {"first", "second"},
				headerorder.HeaderOrderKey: {"x-first", "x-last"},
			}
			writer := newRequestWriter()
			encoder := dynamic.NewEncoder(dynamic.EncoderOptions{})
			cause := errors.New("QPACK encoder rejected section")
			encoded := 0
			writer.encodeQPACK = func(id quic.StreamID, fields []base.HeaderField) ([]byte, error) {
				encoded++
				input := make([]dynamic.Field, len(fields))
				for i, field := range fields {
					input[i] = dynamic.Field{Name: field.Name, Value: field.Value}
				}

				if mode == "encoder-error" {
					return nil, cause
				}

				return encoder.Encode(uint64(id), input, nil)
			}
			switch mode {
			case "invalid-name":
				request.Trailer = http.Header{"bad\nname": {"value"}}
			case "invalid-value":
				request.Trailer = http.Header{"X-Trailer": {"bad\nvalue"}}
			case "filtered":
				request.Trailer = http.Header{"Content-Length": {"10"}}
			}

			var output bytes.Buffer
			var destination io.Writer = &output
			if mode == "write-error" {
				destination = &requestHeaderResultWriter{err: cause}
			}

			recorder := new(events.Recorder)
			err = writer.WriteRequestTrailer(destination, request, 0, recorder)
			switch mode {
			case "invalid-name", "invalid-value":
				require.ErrorContains(t, err, "invalid HTTP trailer")
				require.Zero(t, encoded)
				require.Empty(t, recorder.Events())
			case "filtered":
				require.NoError(t, err)
				require.Zero(t, encoded)
				require.Empty(t, recorder.Events())
			case "encoder-error", "write-error":
				require.ErrorIs(t, err, cause)
				require.Equal(t, 1, encoded)
			default:
				require.NoError(t, err)
				require.Equal(t, 1, encoded)
				parser := frameParser{r: &output}
				frame, err := parser.ParseNext(nil)
				require.NoError(t, err)
				header := frame.(*headersFrame)
				require.EqualValues(t, output.Len(), header.Length)
				decode := base.NewDecoder().Decode(output.Bytes())
				var fields []base.HeaderField
				for {
					field, err := decode()
					if errors.Is(err, io.EOF) {
						break
					}

					require.NoError(t, err)
					fields = append(fields, field)
				}

				require.Equal(t, []base.HeaderField{
					{Name: "x-first", Value: "first"}, {Name: "x-first", Value: "second"}, {Name: "x-last", Value: "last"},
				}, fields)
				logged := recorder.Events(qlog.FrameCreated{})
				require.Len(t, logged, 1)
				require.IsType(t, qlog.HeadersFrame{}, logged[0].(qlog.FrameCreated).Frame.Frame)
			}
		})
	}
}

func TestRequestHeaderPreparationFailureDoesNotReportHeadersWritten(t *testing.T) {
	for _, mode := range []string{"encoder", "batch-writer"} {
		t.Run(mode, func(t *testing.T) {
			cause := errors.New("request preparation failed")
			writer := newRequestWriter()
			if mode == "encoder" {
				writer.encodeQPACK = func(quic.StreamID, []base.HeaderField) ([]byte, error) { return nil, cause }
			} else {
				writer.writeRequestHeaders = func(io.Writer, *http.Request, quic.StreamID, []byte) error { return cause }
			}

			traced := false
			ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{WroteHeaders: func() { traced = true }})
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/", nil)
			require.NoError(t, err)
			var output bytes.Buffer
			require.ErrorIs(t, writer.WriteRequestHeader(&output, request, false, 0, nil), cause)
			require.False(t, traced)
			require.Empty(t, output.Bytes())
			require.Empty(t, writer.qpackFields, "failed preparation cannot retain fields for the next request")
		})
	}
}
