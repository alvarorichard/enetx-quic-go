package http3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alvarorichard/enetx-g"
	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestStartupPreparationFailureSurvivesConnectionClosure(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "buffered"}[buffered], func(t *testing.T) {
			conn, _ := newConnPair(t)
			cause := errors.New("cannot generate SETTINGS")
			transport := &Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
					t.Error("failed startup reached peer initialization")
					return nil, nil
				},
				PrepareHeaders: func(*http.Request, *quic.Conn) error { t.Error("failed startup reached headers"); return nil },
				WireConfig:     &WireConfig{SettingsGrease: func() (uint64, uint64, error) { return 0, 0, cause }},
			}
			if buffered {
				transport.QPACKConfig = &QPACKConfig{DynamicTable: true}
			}
			client := transport.NewClientConn(conn)
			if buffered {
				client.initialInputReady = make(chan struct{})
			}
			select {
			case <-conn.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("startup error did not close connection")
			}
			// A frozen early decision can reach preparation after TLS/closure
			// progressed. The same known startup cause must win at that boundary.
			early, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
			require.NoError(t, err)
			_, err = client.prepareRequestHeaders(early, true)
			require.ErrorIs(t, err, cause)
			body := &preparationBody{}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			_, err = client.RoundTrip(request)
			require.ErrorIs(t, err, cause)
			var local *RequestPreparationError
			require.ErrorAs(t, err, &local)
			_, retryErr := canRetryRequest(err, request)
			require.ErrorIs(t, retryErr, cause)
			require.Zero(t, body.reads.Load())
			require.EqualValues(t, 1, body.closes.Load())
			require.Empty(t, client.rawConn.streams)
			stream, err := client.OpenRequestStream(t.Context())
			require.Nil(t, stream)
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestStartupNativeFailureKeepsItsPublishedCause(t *testing.T) {
	conn, _ := newConnPair(t)
	require.NoError(t, conn.CloseWithError(71, "native startup failed"))
	client := (&Transport{PrepareHeaders: func(*http.Request, *quic.Conn) error { return nil }}).NewClientConn(conn)
	select {
	case <-client.initialSettingsWritten:
	case <-time.After(time.Second):
		t.Fatal("closed connection retained startup writer")
	}
	require.Error(t, client.initialSettingsErr)
	fallback := errors.New("secondary connection error")
	require.ErrorIs(t, client.preparationFailure(fallback), client.initialSettingsErr)
}

func TestPeerLocalFailureWinsOverNativeStartupWriteFailure(t *testing.T) {
	conn, _ := newConnPair(t, withServerConnectionWindow(3), withServerStreamWindow(3))
	cause := errors.New("authenticated peer prelude failed")
	client := (&Transport{
		InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { return nil, cause },
		WireConfig: &WireConfig{CoalesceInitialSettings: true,
			ControlGreaseFrames: func() ([]GreaseFrame, error) { return []GreaseFrame{{Type: 33, Payload: make([]byte, 4096)}}, nil },
		},
	}).NewClientConn(conn)
	require.ErrorIs(t, client.rawConn.initializePeerSettings(t.Context()), cause)
	select {
	case <-client.initialSettingsWritten:
	case <-time.After(time.Second):
		t.Fatal("peer failure retained blocked startup writer")
	}
	require.Error(t, client.initialSettingsErr)
	var local *RequestPreparationError
	require.NotErrorAs(t, client.initialSettingsErr, &local, "the blocked native writer must fail from connection closure")
	require.ErrorAs(t, client.preparationFailure(context.Cause(conn.Context())), &local)
	require.ErrorIs(t, client.preparationFailure(context.Cause(conn.Context())), cause)
}

func TestRawFirstInitializationFailurePreservesLocalCause(t *testing.T) {
	conn, _ := newConnPair(t)
	cause := errors.New("raw peer initialization failed")
	client := (&Transport{
		InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { return nil, cause },
		PrepareHeaders: func(*http.Request, *quic.Conn) error {
			t.Error("raw caller headers reached automatic preparation")
			return nil
		},
	}).NewRawClientConn(conn)
	stream, err := client.OpenRequestStream(t.Context())
	require.Nil(t, stream)
	require.ErrorIs(t, err, cause)
	var local *RequestPreparationError
	require.ErrorAs(t, err, &local)
	require.Empty(t, client.rawConn.streams)
}
