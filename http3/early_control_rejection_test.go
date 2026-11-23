package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	"github.com/enetx/quic-go/internal/testdata"
	"github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

func TestRejectedEarlyControlGenerationDoesNotCloseQUIC(t *testing.T) {
	for _, scenario := range []string{"caller-replays", "transport-restarts", "feedback-rejection", "dial-waits-confirmation", "request-marker-restart"} {
		t.Run(scenario, func(t *testing.T) {
			testRejectedEarlyControlGeneration(t, scenario)
		})
	}
}

func testRejectedEarlyControlGeneration(t *testing.T, scenario string) {
	markerRestart := scenario == "request-marker-restart"
	restart := scenario == "transport-restarts" || scenario == "dial-waits-confirmation" || markerRestart
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	gate, earlySent := make(chan struct{}), make(chan struct{})
	var release, sent sync.Once
	requestSent := make(chan struct{})
	var reportRequest sync.Once
	defer release.Do(func() { close(gate) })
	var reject atomic.Bool
	serverTLS := testdata.GetTLSConfig().Clone()
	serverTLS.SetSessionTicketKeys([][32]byte{{1, 2, 3}})
	serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if reject.Load() {
			select {
			case <-gate:
			case <-hello.Context().Done():
				return nil, context.Cause(hello.Context())
			}
		}
		return nil, nil
	}
	serverTLS.UnwrapSession = func(identity []byte, state tls.ConnectionState) (*tls.SessionState, error) {
		session, err := serverTLS.DecryptTicket(identity, state)
		if session != nil && reject.Load() {
			session.EarlyData = false
		}
		return session, err
	}

	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	defer udp.Close()
	server := &Server{
		TLSConfig:  serverTLS,
		QUICConfig: &quic.Config{Allow0RTT: true},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, "warm")
		}),
	}
	if scenario == "feedback-rejection" {
		server.QUICConfig.InitialStreamReceiveWindow = 32
		server.QUICConfig.MaxStreamReceiveWindow = 32
	}

	defer server.Close()
	go server.Serve(udp)

	cache := &preconnectSessionCache{
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
		stored:             make(chan struct{}, 4),
	}
	feedbackSent := make(chan struct{})
	var reportFeedback sync.Once
	transport := &Transport{
		EarlyDataRestart: restart,
		TLSClientConfig: &tls.Config{
			ServerName:         "localhost",
			RootCAs:            testdata.GetRootCA(),
			ClientSessionCache: cache,
		},
		WireConfig: &WireConfig{FlushEarlySettings: true},
		QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &settingsWireTrace{onSent: func(packet qlog.PacketSent) {
				if packet.Header.PacketType == qlog.PacketType0RTT {
					for _, frame := range packet.Frames {
						if _, ok := frame.Frame.(*qlog.StreamFrame); ok {
							sent.Do(func() { close(earlySent) })
						}
						if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 0 {
							reportRequest.Do(func() { close(requestSent) })
						}
						if stream, ok := frame.Frame.(*qlog.StreamFrame); ok && stream.StreamID == 6 {
							reportFeedback.Do(func() { close(feedbackSent) })
						}
					}
				}
			}}
		}},
	}
	var markers []bool
	var markerMx sync.Mutex
	var initial atomic.Int32
	if markerRestart {
		transport.InitialPeerSettings = func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { initial.Add(1); return nil, nil }
		transport.PrepareHeaders = func(req *http.Request, _ *quic.Conn) error {
			markerMx.Lock()
			markers = append(markers, IsEarlyRequest(req))
			markerMx.Unlock()
			return nil
		}
	}
	if scenario == "transport-restarts" || markerRestart {
		// Exercise the native asynchronous setup, without the optional
		// OnApplicationReady staging hook used by coalesced clients.
		transport.WireConfig = nil
	}

	customEarly := make(chan *quic.Conn, 1)
	if scenario == "dial-waits-confirmation" {
		// Custom routes may return a verified connection even though their TLS
		// engine already exposed early keys and invoked the transport's hooks.
		transport.Dial = func(ctx context.Context, address string, config *tls.Config, q *quic.Config) (*quic.Conn, error) {
			conn, err := quic.DialAddrEarly(ctx, address, config, q)
			if err != nil {
				return nil, err
			}

			if reject.Load() {
				customEarly <- conn
			}

			select {
			case <-conn.HandshakeComplete():
				return conn, nil
			case <-conn.Context().Done():
				return nil, context.Cause(conn.Context())
			case <-ctx.Done():
				conn.CloseWithError(0, "custom dial canceled")
				return nil, context.Cause(ctx)
			}
		}
	}

	defer transport.Close()

	request, err := http.NewRequestWithContext(ctx, "GET", "https://"+udp.LocalAddr().String(), nil)
	require.NoError(t, err)
	response, err := transport.RoundTrip(request)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	select {
	case <-cache.stored:
	case <-ctx.Done():
		t.Fatal("missing warm session ticket")
	}
	transport.CloseIdleConnections()
	reject.Store(true)
	var conn *quic.Conn
	var prepared chan error
	if scenario == "dial-waits-confirmation" {
		prepared = make(chan error, 1)
		go func() {
			_, err := transport.PreconnectEarly(ctx, udp.LocalAddr().String())
			prepared <- err
		}()
		select {
		case conn = <-customEarly:
		case <-ctx.Done():
			t.Fatal("custom dial did not expose its early TLS connection")
		}
	} else {
		conn, err = transport.PreconnectEarly(ctx, udp.LocalAddr().String())
		require.NoError(t, err)
	}

	select {
	case <-earlySent:
	case <-ctx.Done():
		t.Fatal("control stream never used early encryption")
	}
	type markerResponse struct {
		response *http.Response
		err      error
	}
	var markerResult chan markerResponse
	var earlyRequest *http.Request
	if markerRestart {
		earlyRequest, err = http.NewRequestWithContext(ctx, MethodGet0RTT, request.URL.String(), nil)
		require.NoError(t, err)
		markerResult = make(chan markerResponse, 1)
		go func() {
			response, err := transport.RoundTrip(earlyRequest)
			markerResult <- markerResponse{response, err}
		}()
		select {
		case <-requestSent:
		case <-ctx.Done():
			t.Fatal("early request STREAM was not sent before rejection")
		}
	}

	var feedbackDone chan struct{}
	if scenario == "feedback-rejection" {
		transport.mutex.Lock()
		owner := nativeClient(transport.clients[udp.LocalAddr().String()].clientConn).rawConn
		transport.mutex.Unlock()
		feedback := make(chan []byte, 1)
		// These early instructions are intentionally rejected before the peer
		// can parse them. Exceed remembered credit to retain a real blocked write.
		feedback <- bytes.Repeat([]byte{0x40}, 64<<10)
		feedbackDone = make(chan struct{})
		go func() { owner.writeQPACKFeedback(feedback); close(feedbackDone) }()
		select {
		case <-feedbackSent:
		case <-ctx.Done():
			t.Fatal("the old decoder writer did not reach real early stream credit")
		}
	}

	// Keep the old writer waiting on its stream before TLS retires that stream
	// generation. Rejection is a transport event, not a peer critical-stream reset.
	time.Sleep(10 * time.Millisecond)
	release.Do(func() { close(gate) })
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatal("rejected early setup prevented verified TLS readiness")
	}
	require.True(t, conn.ConnectionState().TLS.DidResume)
	require.False(t, conn.ConnectionState().Used0RTT)
	require.NotEmpty(t, conn.ConnectionState().TLS.VerifiedChains)
	if prepared != nil {
		require.NoError(t, <-prepared)
	}

	if feedbackDone != nil {
		select {
		case <-feedbackDone:
		case <-ctx.Done():
			t.Fatal("the rejected decoder generation retained its blocked writer")
		}
	}

	transport.mutex.Lock()
	owner := nativeClient(transport.clients[udp.LocalAddr().String()].clientConn)
	transport.mutex.Unlock()
	if restart {
		var response *http.Response
		if markerRestart {
			result := <-markerResult
			response, err = result.response, result.err
		} else {
			response, err = transport.RoundTrip(request)
		}
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.Equal(t, "warm", string(body))
		require.NoError(t, response.Body.Close())
		transport.mutex.Lock()
		pooled := transport.clients[udp.LocalAddr().String()].conn
		transport.mutex.Unlock()
		require.Same(t, conn, pooled,
			"a rejected setup generation must restart on the same authenticated QUIC connection")
		if markerRestart {
			require.False(t, IsEarlyRequest(response.Request))
			require.Equal(t, http.MethodGet, response.Request.Method)
			require.Equal(t, MethodGet0RTT, earlyRequest.Method)
			require.False(t, IsEarlyRequest(earlyRequest))
			markerMx.Lock()
			require.Equal(t, []bool{false, true, false}, markers, "warm, early, then authenticated rejected-generation retry")
			markerMx.Unlock()
			require.EqualValues(t, 2, initial.Load())
		}
	} else {
		_, err = owner.RoundTrip(request)
		require.ErrorIs(t, err, quic.Err0RTTRejected)
	}

	select {
	case <-conn.Context().Done():
		t.Fatalf("early worker closed the live QUIC connection: %v", context.Cause(conn.Context()))
	case <-time.After(10 * time.Millisecond):
	}
}
