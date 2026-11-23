package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestInitialPeerSettingsWaitersAndRetiredGeneration(t *testing.T) {
	for _, retire := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "retired"}[retire], func(t *testing.T) {
			conn, _ := newConnPair(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			transport := &Transport{InitialPeerSettings: func(got *quic.Conn) (g.MapOrd[uint64, uint64], error) {
				require.Same(t, conn, got)
				require.True(t, got.ConnectionState().TLS.HandshakeComplete)
				calls.Add(1)
				close(entered)
				<-release
				return orderedTestSettings(map[uint64]uint64{6: 123}), nil
			}}
			client := transport.NewClientConn(conn)
			finished := make(chan error, 1)
			go func() { finished <- client.rawConn.initializePeerSettings(t.Context()) }()
			<-entered
			ctx, cancel := context.WithCancelCause(t.Context())
			waitCtx := &initialSettingsWaitContext{Context: ctx, entered: make(chan struct{})}
			waiting := make(chan error, 1)
			go func() { waiting <- client.rawConn.initializePeerSettings(waitCtx) }()
			<-waitCtx.entered
			cause := errors.New("second request abandoned during shared initialization")
			cancel(cause)
			select {
			case err := <-waiting:
				require.ErrorIs(t, err, cause)
			case <-time.After(time.Second):
				t.Fatal("canceled waiter was retained by another request's callback")
			}

			if retire {
				client.rawConn.retireEarlyData()
			}
			close(release)
			err := <-finished
			if retire {
				require.ErrorIs(t, err, quic.Err0RTTRejected)
				require.Nil(t, client.rawConn.peerSettings.current, "a retired callback cannot publish into the replacement generation")
				fresh := transport.NewClientConn(conn)
				fresh.rawConn.peerSettings.initial = func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
					return orderedTestSettings(map[uint64]uint64{6: 456}), nil
				}
				require.NoError(t, fresh.rawConn.initializePeerSettings(t.Context()))
				require.EqualValues(t, 456, fresh.rawConn.peerFieldSectionLimit())
			} else {
				require.NoError(t, err)
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { require.NoError(t, client.rawConn.initializePeerSettings(t.Context())) })
				}
				wg.Wait()
				require.EqualValues(t, 123, client.rawConn.peerFieldSectionLimit())
			}
			require.EqualValues(t, 1, calls.Load())
			require.NoError(t, context.Cause(conn.Context()))
		})
	}
}

func TestInitialPeerSettingsApplyBeforeWireWithoutCommittingTickets(t *testing.T) {
	conn, peer := newConnPair(t)
	values := orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16, 6: 0, settingExtendedConnect: 1, 0xdead: 9})
	var calls atomic.Int32
	client := (&Transport{
		InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { calls.Add(1); return values, nil },
		QPACKConfig:         &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096},
	}).NewClientConn(conn)
	cache := &settingsRecordingCache{}
	session := &clientSettingsSession{conn: conn, cache: cache}
	client.bindSession(session)
	ticket := settingsTicket(t, nil, true)
	session.Put("opaque-key", ticket)
	require.NoError(t, client.rawConn.initializePeerSettings(t.Context()))
	require.Zero(t, client.rawConn.peerFieldSectionLimit())
	require.Nil(t, session.current)
	require.Len(t, session.pending, 1)
	require.Empty(t, cache.puts)
	select {
	case <-client.ReceivedSettings():
		t.Fatal("authenticated prelude was mislabeled a wire SETTINGS event")
	default:
	}

	values.Insert(6, 9999)
	require.Zero(t, client.rawConn.peerFieldSectionLimit(), "the callback's retained map cannot alter the copied limits")
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	// Literal wire SETTINGS: max-field=500 and explicit extended-CONNECT=0.
	// Omitted QPACK IDs retain the initial limits; zero differs from omission.
	_, err = control.Write([]byte{0, 4, 5, 6, 0x41, 0xf4, 8, 0})
	require.NoError(t, err)
	select {
	case <-client.ReceivedSettings():
	case <-time.After(time.Second):
		t.Fatal("wire SETTINGS did not complete")
	}
	require.EqualValues(t, 1, calls.Load())
	require.EqualValues(t, 500, client.rawConn.peerFieldSectionLimit())
	require.False(t, client.Settings().EnableExtendedConnect)
	require.EqualValues(t, 4096, client.Settings().Other.Get(1).Unwrap())
	require.EqualValues(t, 16, client.Settings().Other.Get(7).Unwrap())
	require.EqualValues(t, 9, client.Settings().Other.Get(0xdead).Unwrap())
	require.EqualValues(t, 500, session.current.MaxFieldSectionSize)
	require.Empty(t, session.current.Other, "ticket metadata must contain the exact wire record, not the overlaid prelude")
	require.Eventually(t, func() bool { cache.mutex.Lock(); defer cache.mutex.Unlock(); return len(cache.puts) == 1 }, time.Second, time.Millisecond)
}

func TestInitialPeerSettingsRawStreamAndEarlyRequestScope(t *testing.T) {
	for _, method := range []string{MethodGet0RTT, MethodHead0RTT} {
		t.Run(method, func(t *testing.T) {
			conn, peer := newConnPair(t)
			<-conn.HandshakeComplete()
			var initial, prepared atomic.Int32
			client := (&Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { initial.Add(1); return nil, nil },
				PrepareHeaders: func(req *http.Request, _ *quic.Conn) error {
					prepared.Add(1)
					require.False(t, IsEarlyRequest(req), "late magic methods initialize after an already completed handshake")
					require.Contains(t, []string{http.MethodGet, http.MethodHead}, req.Method)
					return errors.New("stop before request allocation")
				},
			}).NewRawClientConn(conn)
			req, err := http.NewRequestWithContext(t.Context(), method, "https://localhost/", nil)
			require.NoError(t, err)
			_, err = client.RoundTrip(req)
			require.ErrorContains(t, err, "stop before request allocation")
			require.EqualValues(t, 1, initial.Load(), "late magic methods use authenticated initialization")
			require.EqualValues(t, 1, prepared.Load())
			require.Equal(t, method, req.Method)
			require.False(t, IsEarlyRequest(req), "the caller's request/context remains unmarked")
			stream, err := client.OpenRequestStream(t.Context())
			require.NoError(t, err)
			request, err := http.NewRequest(http.MethodHead, "https://localhost/", nil)
			require.NoError(t, err)
			require.NoError(t, stream.SendRequestHeader(request))
			require.NoError(t, stream.Close())
			remote, err := peer.AcceptStream(t.Context())
			require.NoError(t, err)
			data, err := io.ReadAll(remote)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			require.EqualValues(t, 1, initial.Load())
			require.EqualValues(t, 1, prepared.Load(), "raw caller-supplied headers do not invoke automatic preparation")
		})
	}
}

func TestInitialPeerSettingsRejectInvalidInputsBeforeRequest(t *testing.T) {
	cause := errors.New("authenticated prelude unavailable")
	for name, values := range map[string]g.MapOrd[uint64, uint64]{
		"callback":                   nil,
		"callback-rejection":         nil,
		"datagram":                   orderedTestSettings(map[uint64]uint64{settingDatagram: 2}),
		"datagram-missing-transport": orderedTestSettings(map[uint64]uint64{settingDatagram: 1}),
		"connect":                    orderedTestSettings(map[uint64]uint64{settingExtendedConnect: 2}),
		"identifier-range":           orderedTestSettings(map[uint64]uint64{quicvarint.Max + 1: 0}),
		"value-range":                orderedTestSettings(map[uint64]uint64{6: quicvarint.Max + 1}),
		"duplicate":                  {{Key: 6, Value: 10}, {Key: 6, Value: 20}},
		"reserved-2":                 orderedTestSettings(map[uint64]uint64{2: 0}),
		"reserved-3":                 orderedTestSettings(map[uint64]uint64{3: 0}),
		"reserved-4":                 orderedTestSettings(map[uint64]uint64{4: 0}),
		"reserved-5":                 orderedTestSettings(map[uint64]uint64{5: 0}),
	} {
		t.Run(name, func(t *testing.T) {
			conn, _ := newConnPair(t)
			var calls atomic.Int32
			client := (&Transport{EnableDatagrams: name == "datagram-missing-transport", InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
				calls.Add(1)
				if name == "callback" {
					return nil, cause
				}
				if name == "callback-rejection" {
					return nil, quic.Err0RTTRejected
				}
				return values, nil
			}}).NewClientConn(conn)
			body := &preparationBody{}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			_, err = client.RoundTrip(req)
			var preparation *RequestPreparationError
			require.ErrorAs(t, err, &preparation)
			if name == "callback" {
				require.ErrorIs(t, err, cause)
			}
			if name == "callback-rejection" {
				require.ErrorIs(t, err, quic.Err0RTTRejected)
				var unopened *errConnUnusable
				require.NotErrorAs(t, err, &unopened)
			}
			require.Zero(t, body.reads.Load())
			require.EqualValues(t, 1, body.closes.Load())
			require.Empty(t, client.rawConn.streams)
			select {
			case <-client.ReceivedSettings():
				t.Fatal("invalid prelude fabricated a wire SETTINGS event")
			default:
			}
			_, err = client.OpenRequestStream(t.Context())
			require.ErrorAs(t, err, &preparation)
			require.EqualValues(t, 1, calls.Load())
		})
	}
}

func TestPeerSettingsOverlayPreservesOnlyExplicitValues(t *testing.T) {
	base, err := peerSettingsFrame(orderedTestSettings(map[uint64]uint64{6: 0, settingDatagram: 1, settingExtendedConnect: 1, 1: 4096, 7: 16}))
	require.NoError(t, err)
	zero, err := peerSettingsFrame(orderedTestSettings(map[uint64]uint64{settingDatagram: 0, settingExtendedConnect: 0, 1: 0}))
	require.NoError(t, err)
	merged := overlayPeerSettings(base, zero)
	require.Zero(t, merged.MaxFieldSectionSize)
	require.False(t, merged.Datagram)
	require.False(t, merged.ExtendedConnect)
	require.Zero(t, merged.Other.Get(1).Unwrap())
	require.EqualValues(t, 16, merged.Other.Get(7).Unwrap())
	require.True(t, base.Datagram)
	require.EqualValues(t, 4096, base.Other.Get(1).Unwrap())
	max, err := peerSettingsFrame(orderedTestSettings(map[uint64]uint64{quicvarint.Max: quicvarint.Max, 6: quicvarint.Max}))
	require.NoError(t, err)
	require.EqualValues(t, uint64(quicvarint.Max), max.MaxFieldSectionSize)
	require.EqualValues(t, uint64(quicvarint.Max), max.Other.Get(quicvarint.Max).Unwrap())
}

func TestInitialPeerSettingsShareQPACKOwnerWithoutRepeatingCapacity(t *testing.T) {
	conn, _ := newConnPair(t)
	raw := newRawConn(conn, false, func() {}, nil, nil, nil)
	raw.peerSettings = &clientPeerSettings{ready: make(chan struct{}), initial: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
		return orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16, 6: 1000}), nil
	}}
	// Control startup has not released its writer yet. Complete queued bytes
	// expose duplicate capacity/reset behavior without relying on socket timing.
	q := newClientQPACK(raw, &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096,
		StreamOrder: []QPACKStreamType{QPACKEncoderStream}}, make(chan struct{}), 8)
	raw.clientQPACK = q
	require.NoError(t, q.prepare())
	require.NoError(t, raw.initializePeerSettings(t.Context()))
	require.Equal(t, []byte{0x3f, 0xe1, 0x1f}, <-q.encoder.queue)
	fields := []base.HeaderField{{Name: "x-prelude", Value: "retain-the-entry"}}
	block, err := q.encode(0, fields)
	require.NoError(t, err)
	require.NotZero(t, block[0])
	require.NotEmpty(t, <-q.encoder.queue)
	// A literal empty wire SETTINGS omits both QPACK IDs and the field limit.
	sf, err := parseSettingsFrame(&countingByteReader{Reader: bytes.NewReader(nil)}, 0, 0, nil)
	require.NoError(t, err)
	code, err := raw.applyWirePeerSettings(sf)
	require.NoError(t, err)
	require.Zero(t, code)
	require.Same(t, q, raw.clientQPACK)
	require.Empty(t, q.encoder.queue)
	block, err = q.encode(4, fields)
	require.NoError(t, err)
	require.NotZero(t, block[0])
	require.Empty(t, q.encoder.queue, "wire SETTINGS must retain the entry and not repeat a capacity instruction")
	require.EqualValues(t, 1000, raw.peerFieldSectionLimit())
}

func TestInitialPeerSettingsWireQPACKChangeIsTerminal(t *testing.T) {
	conn, peer := newConnPair(t)
	client := (&Transport{
		InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
			return orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16}), nil
		},
		QPACKConfig: &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096, StreamOrder: []QPACKStreamType{QPACKEncoderStream}},
	}).NewClientConn(conn)
	require.NoError(t, client.rawConn.initializePeerSettings(t.Context()))
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	// A literal wire SETTINGS changes an already authenticated nonzero QPACK
	// maximum. The actual shared encoder rejects it without a partial publish.
	_, err = control.Write([]byte{0, 4, 3, 1, 0x44, 0})
	require.NoError(t, err)
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("incompatible QPACK limits did not close connection")
	}
	var application *quic.ApplicationError
	require.ErrorAs(t, context.Cause(conn.Context()), &application)
	require.Equal(t, quic.ApplicationErrorCode(ErrCodeExcessiveLoad), application.ErrorCode)
	require.ErrorContains(t, application, "incompatible remembered encoder limits")
	require.EqualValues(t, 4096, client.rawConn.peerSettings.current.Other.Get(1).Unwrap())
	select {
	case <-client.ReceivedSettings():
		t.Fatal("incompatible wire settings were committed")
	default:
	}
	require.Nil(t, client.rawConn.settings)
}

type initialSettingsWaitContext struct {
	context.Context
	entered chan struct{}
	calls   atomic.Int32
}

func (c *initialSettingsWaitContext) Done() <-chan struct{} {
	if c.calls.Add(1) == 2 {
		close(c.entered)
	}
	return c.Context.Done()
}

func TestInitialPeerSettingsGenerationCancellationReleasesWaiters(t *testing.T) {
	conn, _ := newConnPair(t)
	entered, release := make(chan struct{}), make(chan struct{})
	client := (&Transport{InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
		close(entered)
		<-release
		return orderedTestSettings(map[uint64]uint64{6: 10}), nil
	}}).NewClientConn(conn)
	owner := make(chan error, 1)
	go func() { owner <- client.rawConn.initializePeerSettings(t.Context()) }()
	<-entered
	waitCtx := &initialSettingsWaitContext{Context: t.Context(), entered: make(chan struct{})}
	waiter := make(chan error, 1)
	go func() { waiter <- client.rawConn.initializePeerSettings(waitCtx) }()
	<-waitCtx.entered // both the TLS gate and the shared-initialization wait have been entered
	client.rawConn.retireEarlyData()
	select {
	case err := <-waiter:
		require.ErrorIs(t, err, quic.Err0RTTRejected)
	case <-time.After(time.Second):
		t.Fatal("retired generation retained a blocked waiter")
	}
	close(release)
	require.ErrorIs(t, <-owner, quic.Err0RTTRejected)
	require.Nil(t, client.rawConn.peerSettings.current)
}

func TestInitialPeerSettingsControlFailureAndRetiredWire(t *testing.T) {
	conn, peer := newConnPair(t)
	cause := errors.New("control-prelude initialization failed")
	client := (&Transport{InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { return nil, cause }}).NewClientConn(conn)
	control, err := peer.OpenUniStream()
	require.NoError(t, err)
	_, err = control.Write([]byte{0, 4, 0})
	require.NoError(t, err)
	select {
	case <-conn.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("invalid control prelude did not terminate its connection")
	}
	select {
	case <-client.ReceivedSettings():
		t.Fatal("failed initialization fabricated a wire SETTINGS event")
	default:
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://localhost/", nil)
	require.NoError(t, err)
	_, err = client.RoundTrip(request)
	require.ErrorIs(t, err, cause)
	var preparation *RequestPreparationError
	require.ErrorAs(t, err, &preparation)

	live, _ := newConnPair(t)
	raw := newRawConn(live, false, func() {}, nil, nil, nil)
	raw.retireEarlyData()
	code, err := raw.applyWirePeerSettings(&settingsFrame{MaxFieldSectionSize: -1})
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	require.Equal(t, ErrCodeInternalError, code)
	require.Nil(t, raw.settings)
	require.NoError(t, context.Cause(live.Context()))
}

func TestInitialPeerSettingsRetirementRetainsUnopenedBody(t *testing.T) {
	conn, _ := newConnPair(t)
	client := (&Transport{InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { return nil, nil }}).NewClientConn(conn)
	client.rawConn.retireEarlyData()
	body := &preparationBody{}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
	require.NoError(t, err)
	_, err = client.RoundTrip(request)
	var unopened *errConnUnusable
	require.ErrorAs(t, err, &unopened)
	require.ErrorIs(t, err, quic.Err0RTTRejected)
	require.Zero(t, body.closes.Load(), "a genuine unopened rejection retains the body for its existing retry owner")
	require.Zero(t, body.reads.Load())
}

func TestInitialPeerSettingsRejectIncompatibleAcceptedEarlyLimits(t *testing.T) {
	for _, mode := range []string{"initial", "wire"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			earlySent := make(chan struct{})
			var sent sync.Once
			var handshakes, accepted, initialized atomic.Int32
			serverTLS := getTLSConfig()
			serverTLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
				if handshakes.Add(1) > 1 {
					select {
					case <-earlySent:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return nil, nil
			}
			packet := newUDPConnLocalhost(t)
			listener, err := quic.ListenEarly(packet, serverTLS, &quic.Config{Allow0RTT: true})
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close(); packet.Close() })
			go func() {
				for {
					conn, err := listener.Accept(ctx)
					if err != nil {
						return
					}
					if accepted.Add(1) > 1 && mode == "wire" {
						// A raw peer does not apply its changed table limit to the
						// client's already-sent early encoder stream first. This
						// isolates the client's SETTINGS compatibility decision.
						go func() {
							select {
							case <-conn.HandshakeComplete():
							case <-ctx.Done():
								return
							}
							control, err := conn.OpenUniStreamSync(ctx)
							if err != nil {
								return
							}
							control.Write([]byte{0, 4, 12, 1, 0x44, 0, 7, 16, 6, 0x80, 1, 0, 0, 8, 1})
							<-conn.Context().Done()
						}()
						continue
					}
					server := &Server{MaxHeaderBytes: 65536,
						AdditionalSettings: orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16}),
						Handler:            http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }),
					}
					go server.ServeQUICConn(conn)
				}
			}()
			cache := &settingsRecordingCache{}
			clientTLS := getTLSClientConfig()
			clientTLS.ClientSessionCache = cache
			transport := &Transport{
				TLSClientConfig: clientTLS,
				QPACKConfig:     &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096, StreamOrder: []QPACKStreamType{QPACKEncoderStream}},
				InitialPeerSettings: func(conn *quic.Conn) (g.MapOrd[uint64, uint64], error) {
					initialized.Add(1)
					limit := uint64(65536)
					if conn.ConnectionState().TLS.DidResume {
						require.True(t, conn.ConnectionState().Used0RTT, "this compatibility error requires genuinely accepted early data")
						if mode == "initial" {
							limit = 100
						}
					}
					return orderedTestSettings(map[uint64]uint64{6: limit}), nil
				},
				QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
					return &settingsWireTrace{onSent: func(packet transportlog.PacketSent) {
						if packet.Header.PacketType != transportlog.PacketType0RTT {
							return
						}
						for _, frame := range packet.Frames {
							if _, ok := frame.Frame.(*transportlog.StreamFrame); ok {
								sent.Do(func() { close(earlySent) })
							}
						}
					}}
				}},
			}
			t.Cleanup(func() { transport.Close() })
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+listener.Addr().String(), nil)
			require.NoError(t, err)
			response, err := transport.RoundTrip(request)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.Eventually(t, func() bool {
				ticket, ok := cache.Get("")
				if !ok {
					return false
				}
				_, ok = ClientSessionSettings(ticket)
				return ok
			}, time.Second, time.Millisecond)
			transport.CloseIdleConnections()
			conn, client, err := transport.dial(ctx, listener.Addr().String())
			require.NoError(t, err)
			defer conn.CloseWithError(0, "")
			_, err = client.RoundTrip(request)
			require.Error(t, err)
			require.EqualValues(t, 2, initialized.Load())
			if mode == "initial" {
				require.ErrorContains(t, err, "reduced remembered HTTP/3 SETTINGS")
				var preparation *RequestPreparationError
				require.ErrorAs(t, err, &preparation)
			} else {
				require.ErrorContains(t, err, "changed remembered nonzero QPACK")
			}
		})
	}
}

func TestReservedHTTP2SettingsRejectedOnActualControlStream(t *testing.T) {
	for _, id := range []byte{2, 3, 4, 5} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			conn, peer := newConnPair(t)
			var initial, prepared atomic.Int32
			client := (&Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { initial.Add(1); return nil, nil },
				PrepareHeaders:      func(*http.Request, *quic.Conn) error { prepared.Add(1); return nil },
			}).NewClientConn(conn)
			session := &clientSettingsSession{conn: conn, cache: &settingsRecordingCache{}}
			client.bindSession(session)
			control, err := peer.OpenUniStream()
			require.NoError(t, err)
			_, err = control.Write([]byte{0, 4, 2, id, 0})
			require.NoError(t, err)
			select {
			case <-conn.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("reserved setting did not close connection")
			}
			var application *quic.ApplicationError
			require.ErrorAs(t, context.Cause(conn.Context()), &application)
			require.Equal(t, quic.ApplicationErrorCode(ErrCodeSettingsError), application.ErrorCode)
			require.ErrorContains(t, application, "reserved HTTP/2 setting")
			select {
			case <-client.ReceivedSettings():
				t.Fatal("invalid wire SETTINGS was committed")
			default:
			}
			require.Nil(t, session.current)
			body := &preparationBody{}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			_, err = client.RoundTrip(request)
			require.Error(t, err)
			require.Zero(t, initial.Load(), "a closed generation must not start its initializer")
			require.Zero(t, prepared.Load())
			require.Zero(t, body.reads.Load())
			require.Zero(t, body.closes.Load(), "an unopened native failure retains ownership for the existing retry")
			retry, retryErr := canRetryRequest(err, request)
			require.NoError(t, retryErr)
			require.Same(t, request, retry)
			require.NoError(t, body.Close())
			require.EqualValues(t, 1, body.closes.Load())
			require.Empty(t, client.rawConn.streams)
		})
	}
}

func TestInitialPeerSettingsAlreadyCanceledRequestDoesNotClaimInitialization(t *testing.T) {
	conn, _ := newConnPair(t)
	var calls atomic.Int32
	client := (&Transport{InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { calls.Add(1); return nil, nil }}).NewClientConn(conn)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, client.rawConn.initializePeerSettings(ctx), context.Canceled)
	require.Zero(t, calls.Load())
	require.NoError(t, client.rawConn.initializePeerSettings(t.Context()))
	require.EqualValues(t, 1, calls.Load())
}

func TestCompletedHandshakeKeepsNativeClosedConnectionAdmission(t *testing.T) {
	conn, _ := newConnPair(t)
	<-conn.HandshakeComplete()
	raw := newRawConn(conn, false, func() {}, nil, nil, nil)
	require.NoError(t, conn.CloseWithError(0, "closed after verified handshake"))
	client := &ClientConn{conn: conn, rawConn: raw}
	require.NoError(t, client.handshakeCancellationError(), "completed cached connections retain native unopened retry admission")
}

type initialHandshakeWaitContext struct {
	context.Context
	entered chan struct{}
}

func (c *initialHandshakeWaitContext) Done() <-chan struct{} {
	close(c.entered)
	return c.Context.Done()
}

func TestInitialPeerSettingsTLSGateCancellation(t *testing.T) {
	for _, mode := range []string{"request", "generation", "roundtrip-request", "roundtrip-generation"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			listener, err := quic.Listen(newUDPConnLocalhost(t), getTLSConfig(), nil)
			require.NoError(t, err)
			t.Cleanup(func() { listener.Close() })
			ready, release := make(chan *quic.Conn, 1), make(chan struct{})
			type dialResult struct {
				conn *quic.Conn
				err  error
			}
			dialed := make(chan dialResult, 1)
			go func() {
				conn, err := quic.Dial(ctx, newUDPConnLocalhost(t), listener.Addr(), getTLSClientConfig(), &quic.Config{ClientHandshake: &quic.ClientHandshake{
					OnApplicationReady: func(conn *quic.Conn) {
						ready <- conn
						select {
						case <-release:
						case <-ctx.Done():
						}
					},
				}})
				dialed <- dialResult{conn, err}
			}()
			var conn *quic.Conn
			select {
			case conn = <-ready:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			var calls, prepared atomic.Int32
			client := (&Transport{
				InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) { calls.Add(1); return nil, nil },
				PrepareHeaders:      func(*http.Request, *quic.Conn) error { prepared.Add(1); return nil },
			}).NewClientConn(conn)
			raw := client.rawConn
			waitingCtx, abandon := context.WithCancelCause(ctx)
			defer abandon(nil)
			waiting := &initialHandshakeWaitContext{Context: waitingCtx, entered: make(chan struct{})}
			finished := make(chan error, 1)
			body := &preparationBody{}
			request, err := http.NewRequestWithContext(waiting, http.MethodPost, "https://localhost/", body)
			require.NoError(t, err)
			go func() {
				if strings.HasPrefix(mode, "roundtrip-") {
					_, err := client.RoundTrip(request)
					finished <- err
				} else {
					finished <- raw.initializePeerSettings(waiting)
				}
			}()
			<-waiting.entered // the real QUIC handshake notification is still held by its callback
			cause := errors.New("request canceled while TLS notification is pending")
			if mode == "request" || mode == "roundtrip-request" {
				abandon(cause)
				if mode == "roundtrip-request" {
					cause = context.Canceled
				}
			} else {
				raw.retireEarlyData()
				cause = quic.Err0RTTRejected
			}
			require.ErrorIs(t, <-finished, cause)
			require.Zero(t, calls.Load(), "settings must not initialize before the authenticated handshake gate")
			require.Zero(t, prepared.Load())
			require.Zero(t, body.reads.Load())
			if mode == "roundtrip-request" {
				require.EqualValues(t, 1, body.closes.Load())
			} else {
				require.Zero(t, body.closes.Load())
			}
			close(release)
			result := <-dialed
			require.NoError(t, result.err)
			t.Cleanup(func() { result.conn.CloseWithError(0, "") })
			peer, err := listener.Accept(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { peer.CloseWithError(0, "") })
		})
	}
}
