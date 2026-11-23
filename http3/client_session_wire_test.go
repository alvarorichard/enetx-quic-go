package http3

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enetx/g"
	"github.com/enetx/http"
	"github.com/enetx/quic-go"
	dynamic "github.com/enetx/quic-go/internal/qpack"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/enetx/quic-go/quicvarint"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

type settingsWireTrace struct {
	onSent func(transportlog.PacketSent)
}

func (r *settingsWireTrace) AddProducer() qlogwriter.Recorder { return r }
func (r *settingsWireTrace) Close() error                     { return nil }
func (r *settingsWireTrace) RecordEvent(event qlogwriter.Event) {
	if packet, ok := event.(transportlog.PacketSent); ok {
		r.onSent(packet)
	}
}

// This independent raw peer decodes the received field section with a new QPACK
// table for each connection. Its second handshake cannot finish until an actual
// 0-RTT request packet is sent. A nonzero Required Insert Count then proves that
// the client used remembered SETTINGS before receiving this connection's frame.
func TestClientTicketSettingsEnableDynamicQPACKOnWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	earlySent := make(chan struct{})
	var once sync.Once
	var handshakes atomic.Int32
	var initialSettings atomic.Int32
	var earlyPreparations atomic.Int32
	var preparations atomic.Int32
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
	type observation struct {
		required       byte
		fields         []base.HeaderField
		resumed, early bool
	}
	observed, failures := make(chan observation, 4), make(chan error, 8)
	go func() {
		for {
			conn, err := listener.Accept(ctx)
			if err != nil {
				return
			}
			go func() {
				defer conn.CloseWithError(0, "")
				decoder := dynamic.NewDecoder(4096, 16, nil)
				defer decoder.Close(context.Canceled)
				go func() {
					for {
						stream, err := conn.AcceptUniStream(ctx)
						if err != nil {
							return
						}
						go func() {
							r := quicvarint.NewReader(stream)
							typ, err := quicvarint.Read(r)
							if err != nil {
								return
							}
							if typ == 2 {
								decoder.ReadEncoder(stream)
							} else {
								io.Copy(io.Discard, stream)
							}
						}()
					}
				}()
				select {
				case <-conn.HandshakeComplete():
				case <-ctx.Done():
					return
				}
				control, err := conn.OpenUniStreamSync(ctx)
				if err != nil {
					failures <- err
					return
				}
				_, err = control.Write((&settingsFrame{MaxFieldSectionSize: 65536, Other: orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16})}).Append([]byte{0}))
				if err != nil {
					failures <- err
					return
				}
				for {
					stream, err := conn.AcceptStream(ctx)
					if err != nil {
						return
					}
					frame, err := (&frameParser{r: stream}).ParseNext(nil)
					if err != nil {
						failures <- err
						return
					}
					header, ok := frame.(*headersFrame)
					if !ok {
						failures <- fmt.Errorf("expected HEADERS, got %T", frame)
						return
					}
					block := make([]byte, header.Length)
					if _, err := io.ReadFull(stream, block); err != nil {
						failures <- err
						return
					}
					fields, err := decoder.Decode(ctx, uint64(stream.StreamID()), block, 65536, nil)
					if err != nil {
						failures <- err
						return
					}
					observed <- observation{block[0], fields, conn.ConnectionState().TLS.DidResume, conn.ConnectionState().Used0RTT}
					response := (&headersFrame{Length: 3}).Append(nil)
					response = append(response, 0, 0, 0xd9) // static :status = 200
					response = (&dataFrame{Length: 2}).Append(response)
					if _, err := stream.Write(append(response, 'o', 'k')); err != nil {
						failures <- err
						return
					}
					stream.Close()
				}
			}()
		}
	}()
	cache := &settingsRecordingCache{}
	clientTLS := getTLSClientConfig()
	clientTLS.ClientSessionCache = cache
	transport := &Transport{TLSClientConfig: clientTLS,
		PrepareHeaders: func(req *http.Request, _ *quic.Conn) error {
			index := preparations.Add(1)
			early := IsEarlyRequest(req)
			require.Equal(t, index == 2 || index == 3, early, "cold and warm authenticated magic requests initialize normally")
			if early {
				earlyPreparations.Add(1)
			}
			return nil
		},
		InitialPeerSettings: func(*quic.Conn) (g.MapOrd[uint64, uint64], error) {
			initialSettings.Add(1)
			return orderedTestSettings(map[uint64]uint64{1: 4096, 7: 16, 6: 65536}), nil
		},
		QPACKConfig: &QPACKConfig{DynamicTable: true, EncoderTableCapacity: 4096, StreamOrder: []QPACKStreamType{QPACKEncoderStream}},
		QUICConfig: &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &settingsWireTrace{onSent: func(packet transportlog.PacketSent) {
				if packet.Header.PacketType != transportlog.PacketType0RTT {
					return
				}
				for _, frame := range packet.Frames {
					if stream, ok := frame.Frame.(*transportlog.StreamFrame); ok && stream.StreamID == 0 {
						once.Do(func() { close(earlySent) })
					}
				}
			}}
		}},
	}
	t.Cleanup(func() { transport.Close() })
	for attempt := range 3 {
		req, err := http.NewRequestWithContext(ctx, MethodGet0RTT, "https://"+listener.Addr().String(), nil)
		require.NoError(t, err)
		req.Header.Set("X-Ticket-Probe", "fresh-dynamic-entry")
		response, err := transport.RoundTrip(req)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, err)
		require.NoError(t, response.Body.Close())
		require.True(t, bytes.Equal(body, []byte("ok")))
		select {
		case got := <-observed:
			t.Logf("connection %d: resumed=%t early=%t required-insert-count-byte=%d", attempt+1, got.resumed, got.early, got.required)
			require.Contains(t, got.fields, base.HeaderField{Name: "x-ticket-probe", Value: "fresh-dynamic-entry"})
			require.Equal(t, attempt > 0, got.resumed)
			require.Equal(t, attempt > 0, got.early)
			if attempt > 0 {
				require.NotZero(t, got.required, "restored SETTINGS must enable early dynamic references")
			}
		case err := <-failures:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		// The early response can finish before the asynchronous control reader
		// processes this connection's SETTINGS. Wait for that real wire event
		// before closing the connection or asserting authenticated init counts.
		transport.mutex.Lock()
		active := nativeClient(transport.clients[authorityAddr(listener.Addr().String())].clientConn)
		transport.mutex.Unlock()
		select {
		case <-active.ReceivedSettings():
		case <-ctx.Done():
			t.Fatal("missing definitive SETTINGS before connection teardown")
		}
		require.Eventually(t, func() bool {
			state, ok := cache.Get("")
			if !ok {
				return false
			}
			_, ok = ClientSessionSettings(state)
			return ok
		}, time.Second, time.Millisecond)
		if attempt == 2 {
			// A warm request after accepted 0-RTT is no longer an early
			// preparation, although ConnectionState.Used0RTT remains true.
			// This allows a caller's live connection policy after cache clearing.
			warm := req.Clone(ctx)
			response, err := transport.RoundTrip(warm)
			require.NoError(t, err)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.False(t, IsEarlyRequest(response.Request))
			select {
			case got := <-observed:
				require.True(t, got.early)
				require.NotZero(t, got.required)
			case err := <-failures:
				t.Fatal(err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		transport.CloseIdleConnections()
	}
	require.EqualValues(t, 3, initialSettings.Load(), "fresh authenticated settings initialize once after each early request's TLS gate")
	require.EqualValues(t, 4, preparations.Load())
	require.EqualValues(t, 2, earlyPreparations.Load())
}
