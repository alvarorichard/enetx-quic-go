package http3

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	httpcommon "github.com/enetx/http/headerorder"
	"github.com/enetx/quic-go"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

type preparationBody struct {
	reader        io.Reader
	reads, closes atomic.Int32
}

func (b *preparationBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *preparationBody) Close() error { b.closes.Add(1); return nil }

type preparedWireRequest struct {
	fields []base.HeaderField
	body   string
	err    error
}

// Decode actual request bytes using the independent static QPACK decoder. The
// peer withholds its SETTINGS, so the first request proves prelude initialization
// does not wait for a wire SETTINGS event or fabricate that event.
func readPreparedRequest(peer *quic.Conn, ctx context.Context) preparedWireRequest {
	stream, err := peer.AcceptStream(ctx)
	if err != nil {
		return preparedWireRequest{err: err}
	}
	frame, err := (&frameParser{r: stream}).ParseNext(nil)
	if err != nil {
		return preparedWireRequest{err: err}
	}
	header, ok := frame.(*headersFrame)
	if !ok {
		return preparedWireRequest{err: errors.New("first request frame is not HEADERS")}
	}
	block := make([]byte, header.Length)
	if _, err := io.ReadFull(stream, block); err != nil {
		return preparedWireRequest{err: err}
	}
	var fields []base.HeaderField
	decode := base.NewDecoder().Decode(block)
	for {
		field, err := decode()
		if err == io.EOF {
			break
		}
		if err != nil {
			return preparedWireRequest{err: err}
		}
		fields = append(fields, field)
	}
	var body strings.Builder
	parser := &frameParser{r: stream}
	for {
		frame, err := parser.ParseNext(nil)
		if err == io.EOF {
			break
		}
		if err != nil {
			return preparedWireRequest{err: err}
		}
		data, ok := frame.(*dataFrame)
		if !ok {
			return preparedWireRequest{err: errors.New("unexpected upload frame")}
		}
		if _, err := io.CopyN(&body, stream, int64(data.Length)); err != nil {
			return preparedWireRequest{err: err}
		}
	}
	if _, err := stream.Write([]byte{1, 3, 0, 0, 0xd9}); err != nil {
		return preparedWireRequest{err: err}
	}
	if err := stream.Close(); err != nil {
		return preparedWireRequest{err: err}
	}
	return preparedWireRequest{fields: fields, body: body.String()}
}

func TestPrepareHeadersPrivateContextAndOrderedWireAcrossClients(t *testing.T) {
	for _, mode := range []string{"pooled", "direct", "replacement"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, peer := newConnPair(t)
			type contextKey struct{}
			var prepared, initial atomic.Int32
			transport := &Transport{
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) { return conn, nil },
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
					initial.Add(1)
					return orderedTestSettings(map[uint64]uint64{6: 65536}), nil
				},
				PrepareHeaders: func(request *http.Request, selected *quic.Conn) error {
					require.Same(t, conn, selected)
					require.False(t, IsEarlyRequest(request))
					require.EqualValues(t, 1, initial.Load())
					prepared.Add(1)
					request.Header.Set("X-Before", "private-value")
					request.Header.Set("X-Added", "connection-value")
					request.Header[httpcommon.HeaderOrderKey] = []string{"x-before", "x-added"}
					*request = *request.WithContext(context.WithValue(request.Context(), contextKey{}, "derived"))
					return nil
				},
			}
			t.Cleanup(func() { transport.Close() })
			var roundTrip func(*http.Request) (*http.Response, error)
			switch mode {
			case "pooled":
				roundTrip = transport.RoundTrip
			case "direct":
				roundTrip = transport.NewClientConn(conn).RoundTrip
			case "replacement":
				old := transport.NewClientConn(conn)
				wrapper := newEarlyRestartClient(old, func() *ClientConn { return transport.NewClientConn(conn) })
				wrapper.reject()
				wrapper.applicationReady()
				roundTrip = wrapper.RoundTrip
			}
			observed := make(chan preparedWireRequest, 1)
			go func() { observed <- readPreparedRequest(peer, ctx) }()
			body := &preparationBody{reader: strings.NewReader("one upload")}
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/upload", body)
			require.NoError(t, err)
			request.ContentLength = int64(len("one upload"))
			request.Header.Set("X-Before", "caller-value")
			response, err := roundTrip(request)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			got := <-observed
			require.NoError(t, got.err)
			require.Equal(t, "one upload", got.body)
			var names []string
			for _, field := range got.fields {
				names = append(names, field.Name)
				require.NotEqual(t, httpcommon.HeaderOrderKey, field.Name)
			}
			require.Less(t, slices.Index(names, "x-before"), slices.Index(names, "x-added"))
			require.Contains(t, got.fields, base.HeaderField{Name: "x-before", Value: "private-value"})
			require.Contains(t, got.fields, base.HeaderField{Name: "x-added", Value: "connection-value"})
			require.Equal(t, "caller-value", request.Header.Get("X-Before"))
			require.Empty(t, request.Header.Get("X-Added"))
			require.Nil(t, request.Context().Value(contextKey{}))
			require.Equal(t, "derived", response.Request.Context().Value(contextKey{}))
			require.Equal(t, "connection-value", response.Request.Header.Get("X-Added"))
			require.EqualValues(t, 1, prepared.Load())
			require.Eventually(t, func() bool { return body.closes.Load() == 1 }, time.Second, time.Millisecond)
		})
	}
}

func TestPrepareHeadersErrorsCloseUnsentBodyExactlyOnce(t *testing.T) {
	cause := errors.New("local header preparation failed")
	for _, mode := range []string{"callback", "extended-connect", "name", "value", "derived-cancel", "late-magic-derived-cancel", "request-cancel", "connection-close"} {
		t.Run(mode, func(t *testing.T) {
			conn, _ := newConnPair(t)
			<-conn.HandshakeComplete()
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			var calls atomic.Int32
			transport := &Transport{
				Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) { return conn, nil },
				PrepareHeaders: func(request *http.Request, selected *quic.Conn) error {
					calls.Add(1)
					require.False(t, IsEarlyRequest(request))
					switch mode {
					case "callback", "extended-connect":
						return cause
					case "name":
						request.Header["invalid name"] = []string{"value"}
					case "value":
						request.Header["X-Field"] = []string{"invalid\r\nvalue"}
					case "derived-cancel", "late-magic-derived-cancel":
						derived, cancel := context.WithCancelCause(request.Context())
						cancel(cause)
						*request = *request.WithContext(derived)
					case "request-cancel":
						cancel(cause)
					case "connection-close":
						require.NoError(t, selected.CloseWithError(101, "closed during preparation"))
					}
					return nil
				},
			}
			t.Cleanup(func() { transport.Close() })
			body := &preparationBody{}
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			if mode == "extended-connect" {
				request.Method, request.Proto = http.MethodConnect, "websocket"
			}
			if mode == "late-magic-derived-cancel" {
				request.Method = MethodGet0RTT
			}
			var reopened atomic.Int32
			request.GetBody = func() (io.ReadCloser, error) { reopened.Add(1); return body, nil }
			_, err = transport.RoundTrip(request)
			require.Error(t, err)
			if mode != "request-cancel" && mode != "connection-close" {
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
			}
			require.EqualValues(t, 1, calls.Load())
			require.Zero(t, body.reads.Load())
			require.EqualValues(t, 1, body.closes.Load())
			require.Zero(t, reopened.Load())
			require.False(t, IsEarlyRequest(request))
		})
	}
}

func TestPrepareHeadersLocalRejectionCannotReplayRetiredBody(t *testing.T) {
	conn, _ := newConnPair(t)
	var wrapper *earlyRestartClient
	var calls int
	client := (&Transport{PrepareHeaders: func(*http.Request, *quic.Conn) error {
		calls++
		wrapper.reject()
		return quic.Err0RTTRejected
	}}).NewClientConn(conn)
	wrapper = newEarlyRestartClient(client, func() *ClientConn { t.Fatal("a local preparation failure cannot replay"); return nil })
	body := &preparationBody{}
	request, err := http.NewRequestWithContext(t.Context(), MethodGet0RTT, "https://localhost/", body)
	require.NoError(t, err)
	_, err = wrapper.RoundTrip(request)
	var preparation *RequestPreparationError
	require.ErrorAs(t, err, &preparation)
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	require.Equal(t, 1, calls)
	require.Zero(t, body.reads.Load())
	require.EqualValues(t, 1, body.closes.Load())
}

func TestPrepareHeadersCancellationAndBodyOwnerBoundaries(t *testing.T) {
	for _, kind := range []string{"request", "generation"} {
		t.Run(kind, func(t *testing.T) {
			conn, _ := newConnPair(t)
			client := (&Transport{PrepareHeaders: func(*http.Request, *quic.Conn) error { t.Fatal("canceled preparation reached callback"); return nil }}).NewClientConn(conn)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "request" {
				cancel()
			} else {
				client.rawConn.retireEarlyData()
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://localhost/", nil)
			require.NoError(t, err)
			_, err = client.prepareRequestHeaders(request, false)
			if kind == "request" {
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
			} else {
				var unopened *errConnUnusable
				require.ErrorAs(t, err, &unopened)
			}
		})
	}
	request, err := http.NewRequest(http.MethodGet, "https://localhost/", http.NoBody)
	require.NoError(t, err)
	require.Same(t, request, requestWithPreparationBody(request))
	body := &preparationBody{}
	request.Body = body
	owned := requestWithPreparationBody(request)
	require.Same(t, owned, requestWithPreparationBody(owned))
	require.NotSame(t, request, owned)
	require.NoError(t, owned.Body.Close())
	require.NoError(t, owned.Body.Close())
	require.EqualValues(t, 1, body.closes.Load())
}

func TestInitialPeerSettingsFirstFieldSectionZeroExactAndOverflow(t *testing.T) {
	var exact uint64
	for _, mode := range []string{"measure", "exact", "overflow", "zero"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			conn, peer := newConnPair(t)
			limit := uint64(1 << 30)
			switch mode {
			case "exact":
				limit = exact
			case "overflow":
				limit = exact - 1
			case "zero":
				limit = 0
			}
			client := (&Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
					return orderedTestSettings(map[uint64]uint64{6: limit}), nil
				},
				PrepareHeaders: func(req *http.Request, _ *quic.Conn) error {
					req.Header.Set("X-Prepared", "field-limit-probe")
					return nil
				},
			}).NewClientConn(conn)
			body := &preparationBody{reader: strings.NewReader("bytes")}
			request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://localhost/", body)
			require.NoError(t, err)
			request.ContentLength = 5
			var reopened atomic.Int32
			request.GetBody = func() (io.ReadCloser, error) {
				reopened.Add(1)
				return nil, errors.New("GetBody must not run during preparation")
			}
			observed := make(chan preparedWireRequest, 1)
			if mode == "measure" || mode == "exact" {
				go func() { observed <- readPreparedRequest(peer, ctx) }()
			}
			response, err := client.RoundTrip(request)
			if mode == "measure" || mode == "exact" {
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				got := <-observed
				require.NoError(t, got.err)
				require.Equal(t, "bytes", got.body)
				var size uint64
				for _, field := range got.fields {
					size += uint64(len(field.Name) + len(field.Value) + 32)
				}
				if mode == "measure" {
					exact = size
				} else {
					require.Equal(t, exact, size)
				}
			} else {
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
				require.ErrorContains(t, err, "exceeds peer limit")
				require.Zero(t, body.reads.Load())
			}
			require.Eventually(t, func() bool { return body.closes.Load() == 1 }, time.Second, time.Millisecond)
			require.Zero(t, reopened.Load())
		})
	}
}

func TestPrepareHeadersGoAwayRetryRetainsUnopenedUnsafeBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, peer := newConnPair(t)
	var prepared, reopened atomic.Int32
	transport := &Transport{PrepareHeaders: func(req *http.Request, _ *quic.Conn) error {
		prepared.Add(1)
		req.Header.Set("X-Prepared", "private-on-each-connection")
		return nil
	}}
	old := transport.NewClientConn(conn)
	// A legitimate low-level stream keeps the draining connection alive while
	// a real GOAWAY prevents the next RoundTrip from opening its upload stream.
	active, err := old.OpenRequestStream(ctx)
	require.NoError(t, err)
	defer active.CancelRead(quic.StreamErrorCode(ErrCodeRequestCanceled))
	defer active.CancelWrite(quic.StreamErrorCode(ErrCodeRequestCanceled))
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0, 7, 1, 0}) // SETTINGS {}, GOAWAY streamID=0
	require.NoError(t, err)
	select {
	case <-old.goAwayCtx.Done():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	body := &preparationBody{reader: strings.NewReader("unsafe upload once")}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost/", body)
	require.NoError(t, err)
	request.ContentLength = int64(len("unsafe upload once"))
	request.GetBody = func() (io.ReadCloser, error) {
		reopened.Add(1)
		return nil, errors.New("unopened upload must not be reopened")
	}
	_, err = old.RoundTrip(request)
	require.ErrorIs(t, err, errGoAway)
	require.Zero(t, body.reads.Load())
	require.Zero(t, body.closes.Load(), "the existing retry owner still owns this unsent body")
	retry, err := canRetryRequest(err, request)
	require.NoError(t, err)
	require.Same(t, request, retry)
	freshConn, freshPeer := newConnPair(t)
	fresh := transport.NewClientConn(freshConn)
	observed := make(chan preparedWireRequest, 1)
	go func() { observed <- readPreparedRequest(freshPeer, ctx) }()
	response, err := fresh.RoundTrip(retry)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	got := <-observed
	require.NoError(t, got.err)
	require.Equal(t, "unsafe upload once", got.body)
	require.EqualValues(t, 2, prepared.Load())
	require.Zero(t, reopened.Load())
	require.Eventually(t, func() bool { return body.closes.Load() == 1 }, time.Second, time.Millisecond)
	require.Empty(t, request.Header.Get("X-Prepared"))
}

func TestPrepareHeadersCachedBodyOwnership(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("confirmed=%t/cached=%t", confirmed, cached), func(t *testing.T) {
				var calls atomic.Int32
				transport := &Transport{PrepareHeaders: func(*http.Request, *quic.Conn) error {
					calls.Add(1)
					return errors.New("local cached preparation failure")
				}}
				t.Cleanup(func() { transport.Close() })
				if cached {
					conn, _ := newConnPair(t)
					<-conn.HandshakeComplete()
					transport.Dial = func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) { return conn, nil }
					require.NoError(t, transport.Preconnect(t.Context(), "localhost:443"))
				}
				body := &preparationBody{}
				request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
				require.NoError(t, err)
				roundTrip := transport.RoundTripCached
				if confirmed {
					roundTrip = transport.RoundTripCachedReady
				}
				_, err = roundTrip(request)
				if cached {
					var preparation *RequestPreparationError
					require.ErrorAs(t, err, &preparation)
					require.EqualValues(t, 1, calls.Load())
					require.EqualValues(t, 1, body.closes.Load())
				} else {
					require.ErrorIs(t, err, ErrNoCachedConn)
					require.Zero(t, calls.Load())
					require.Zero(t, body.closes.Load(), "an initial cache miss retains caller ownership")
				}
				require.Zero(t, body.reads.Load())
			})
		}
	}
}

func TestEarlyPreparationContextIsFrozenPrivateAndResetForNormalRequests(t *testing.T) {
	for _, method := range []string{MethodGet0RTT, MethodHead0RTT} {
		t.Run(method, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			listener, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			ready, release := make(chan *quic.Conn, 1), make(chan struct{})
			type result struct {
				response *http.Response
				err      error
			}
			type dialResult struct {
				conn *quic.Conn
				err  error
			}
			dialed := make(chan dialResult, 1)
			go func() {
				conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), listener.Addr(), getTLSClientConfig(), &quic.Config{ClientHandshake: &quic.ClientHandshake{OnApplicationReady: func(conn *quic.Conn) {
					ready <- conn
					select {
					case <-release:
					case <-ctx.Done():
					}
				}}})
				dialed <- dialResult{conn, err}
			}()
			var conn *quic.Conn
			select {
			case conn = <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			t.Cleanup(func() { conn.CloseWithError(0, "") })
			type contextKey struct{}
			var flags []bool
			var initialized atomic.Int32
			earlyCancel := errors.New("early preparation derived context canceled")
			var earlyPrepared *http.Request
			entered := make(chan struct{})
			client := (&Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { initialized.Add(1); return nil, nil },
				PrepareHeaders: func(req *http.Request, _ *quic.Conn) error {
					flags = append(flags, IsEarlyRequest(req))
					if len(flags) == 1 {
						close(entered)
						select {
						case <-conn.HandshakeComplete():
						case <-ctx.Done():
							return ctx.Err()
						}
						require.True(t, IsEarlyRequest(req), "handshake completion during preparation cannot change its frozen decision")
						if method == MethodHead0RTT {
							derived, cancel := context.WithCancelCause(req.Context())
							cancel(earlyCancel)
							*req = *req.WithContext(derived)
							earlyPrepared = req
							return nil
						}
					}
					*req = *req.WithContext(context.WithValue(req.Context(), contextKey{}, "derived"))
					return nil
				},
			}).NewClientConn(conn)
			request, err := http.NewRequestWithContext(ctx, method, "https://localhost/", nil)
			require.NoError(t, err)
			body := &preparationBody{}
			if method == MethodHead0RTT {
				request.Body = body
			}
			require.False(t, IsEarlyRequest(nil))
			require.False(t, IsEarlyRequest(request))
			responseReady := make(chan result, 1)
			go func() { response, err := client.RoundTrip(request); responseReady <- result{response, err} }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			close(release)
			dial := <-dialed
			require.NoError(t, dial.err)
			peer, err := listener.Accept(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { peer.CloseWithError(0, "") })
			observed := make(chan preparedWireRequest, 3)
			requestCount := 3
			if method == MethodHead0RTT {
				requestCount = 1
			}
			go func() {
				for range requestCount {
					observed <- readPreparedRequest(peer, ctx)
				}
			}()
			gotResponse := <-responseReady
			if method == MethodHead0RTT {
				var local *RequestPreparationError
				require.ErrorAs(t, gotResponse.err, &local)
				require.ErrorIs(t, gotResponse.err, earlyCancel)
				require.True(t, IsEarlyRequest(earlyPrepared))
				require.False(t, IsEarlyRequest(request))
				require.NoError(t, request.Context().Err())
				require.Zero(t, body.reads.Load())
				require.EqualValues(t, 1, body.closes.Load())
				require.Zero(t, initialized.Load())
				warm, err := http.NewRequestWithContext(ctx, method, "https://localhost/", nil)
				require.NoError(t, err)
				response, err := client.RoundTrip(warm)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				require.NoError(t, (<-observed).err)
				require.False(t, IsEarlyRequest(response.Request))
				require.Equal(t, []bool{true, false}, flags)
				require.EqualValues(t, 1, initialized.Load())
				return
			}
			require.NoError(t, gotResponse.err)
			response := gotResponse.response
			require.NoError(t, response.Body.Close())
			require.NoError(t, (<-observed).err)
			require.True(t, IsEarlyRequest(response.Request))
			require.Zero(t, initialized.Load())
			require.Equal(t, "derived", response.Request.Context().Value(contextKey{}))
			require.Nil(t, request.Context().Value(contextKey{}))
			require.False(t, IsEarlyRequest(request))
			require.Equal(t, method, request.Method)
			// Reusing a sent request must replace the inherited early marker.
			normal := response.Request.Clone(response.Request.Context())
			response, err = client.RoundTrip(normal)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.NoError(t, (<-observed).err)
			require.True(t, IsEarlyRequest(normal))
			require.False(t, IsEarlyRequest(response.Request))
			require.EqualValues(t, 1, initialized.Load())
			warm := response.Request.Clone(ctx)
			warm.Method = method
			response, err = client.RoundTrip(warm)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.NoError(t, (<-observed).err)
			require.False(t, IsEarlyRequest(response.Request), "warm magic methods initialize normally")
			require.EqualValues(t, 1, initialized.Load())
			require.Equal(t, []bool{true, false, false}, flags)
		})
	}
}

func TestPreparationHooksKeepClosedConnectionRetryOwnership(t *testing.T) {
	for _, initial := range []bool{false, true} {
		t.Run(fmt.Sprint(initial), func(t *testing.T) {
			conn, _ := newConnPair(t)
			<-conn.HandshakeComplete()
			var calls atomic.Int32
			transport := &Transport{PrepareHeaders: func(*http.Request, *quic.Conn) error { calls.Add(1); return nil }}
			if initial {
				transport.InitialPeerSettings = func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { return nil, nil }
			}
			client := transport.NewClientConn(conn)
			require.NoError(t, client.rawConn.initializePeerSettings(t.Context()))
			require.NoError(t, conn.CloseWithError(0, "closed cached connection"))
			body := &preparationBody{}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			_, err = client.RoundTrip(request)
			var unopened *errConnUnusable
			require.ErrorAs(t, err, &unopened)
			var local *RequestPreparationError
			require.NotErrorAs(t, err, &local)
			retry, err := canRetryRequest(err, request)
			require.NoError(t, err)
			require.Same(t, request, retry)
			require.Zero(t, body.reads.Load())
			require.Zero(t, body.closes.Load())
			require.Zero(t, calls.Load(), "a closed selected connection never reaches header preparation")
			require.NoError(t, body.Close())
		})
	}
}

func TestUnconfiguredEarlyMethodKeepsNativeBufferedInputBypass(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, peer := newConnPair(t)
	<-conn.HandshakeComplete()
	client := (&Transport{QPACKConfig: &QPACKConfig{DynamicTable: true}}).NewClientConn(conn)
	// This per-dial handoff is independent of TLS completion. Without either
	// new hook, a magic method retains its existing nonblocking input bypass.
	input := make(chan struct{})
	client.initialInputReady = input
	defer close(input)
	observed := make(chan preparedWireRequest, 1)
	go func() { observed <- readPreparedRequest(peer, ctx) }()
	request, err := http.NewRequestWithContext(ctx, MethodGet0RTT, "https://localhost/", nil)
	require.NoError(t, err)
	response, err := client.RoundTrip(request)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.NoError(t, (<-observed).err)
	require.Equal(t, MethodGet0RTT, request.Method)
	require.Equal(t, http.MethodGet, response.Request.Method)
}
