package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestInitialSettingsFailureIsReportedAndLoggedBeforeConnectionClose(t *testing.T) {
	conn, _ := newConnPair(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	client := newClientConnWithWire(conn, false, nil, 0, false, logger, &WireConfig{
		CoalesceInitialSettings: true,
		RequestBodyBufferSize:   -1,
	})
	err := client.waitInitialSettings(t.Context())
	var preparation *RequestPreparationError
	require.ErrorAs(t, err, &preparation)
	require.ErrorContains(t, err, "request body buffer size")
	select {
	case <-conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("invalid settings did not close the connection")
	}

	require.Contains(t, logs.String(), "setting up connection failed")
	var closed *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &closed)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeInternalError), closed.ErrorCode)
}

func TestTransportRejectsWireConfigurationBeforeDial(t *testing.T) {
	transport := &Transport{
		WireConfig: &WireConfig{MaxDataFrameSize: -1},
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			t.Error("invalid wire configuration reached the network")
			return nil, errors.New("unexpected dial")
		},
	}
	defer transport.Close()
	err := transport.Preconnect(t.Context(), "localhost:443")
	require.ErrorContains(t, err, "maximum DATA frame size")
}

func TestCachedRoundTripClosesRejectedBody(t *testing.T) {
	transport := &Transport{WireConfig: &WireConfig{MaxDataFrameSize: -1}}
	defer transport.Close()
	for name, roundTrip := range map[string]func(*http.Request) (*http.Response, error){
		"cached": transport.RoundTripCached, "confirmed-cached": transport.RoundTripCachedReady,
	} {
		t.Run(name, func(t *testing.T) {
			body := &earlyReplayBody{}
			request, err := http.NewRequest(http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			response, err := roundTrip(request)
			require.Nil(t, response)
			require.ErrorContains(t, err, "maximum DATA frame size")
			require.Equal(t, 1, body.closes)
		})
	}
}
