package http3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/enetx/quic-go"
	transportlog "github.com/enetx/quic-go/qlog"
	"github.com/enetx/quic-go/qlogwriter"
	"github.com/stretchr/testify/require"
)

type admissionPriorityRecorder struct {
	entered, release chan struct{}
	once             sync.Once
}

func (r *admissionPriorityRecorder) RecordEvent(event qlogwriter.Event) {
	if _, ok := event.(transportlog.StreamPriorityUpdated); ok {
		r.once.Do(func() {
			close(r.entered)
			<-r.release
		})
	}
}

func (*admissionPriorityRecorder) Close() error { return nil }

func TestRetirementBetweenStreamCreationAndTrackingRejectsAdmission(t *testing.T) {
	recorder := &admissionPriorityRecorder{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(recorder.release) })
	conn, _ := newConnPair(t, withClientRecorder(recorder))
	client := (&Transport{StreamPriority: &StreamPriority{Urgency: 1}}).NewClientConn(conn)
	require.NoError(t, client.waitInitialSettings(t.Context()))
	existing, err := conn.OpenStream()
	require.NoError(t, err)
	require.NotNil(t, client.rawConn.trackStream(existing, true))
	result := make(chan error, 1)
	go func() {
		stream, err := client.OpenRequestStream(t.Context())
		if stream != nil {
			t.Error("retirement cannot admit the concurrently opened request")
		}
		result <- err
	}()
	select {
	case <-recorder.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stream creation did not reach the normal priority trace event")
	}

	// The existing recorder API supplies a scheduling barrier after stream
	// creation. Retirement must still win before HTTP/3 tracking takes ownership.
	client.retire()
	release.Do(func() { close(recorder.release) })
	select {
	case err := <-result:
		require.ErrorIs(t, err, errGoAway)
	case <-time.After(5 * time.Second):
		t.Fatal("retirement did not release the concurrent request")
	}

	require.Len(t, client.rawConn.streams, 1)
	require.NoError(t, conn.Context().Err(), "the already admitted stream retains its connection")
}

func TestEarlyRetirementUnblocksStreamAdmissionWaitingForPeerCredit(t *testing.T) {
	blocked := make(chan struct{})
	var once sync.Once
	recorder := &settingsWireTrace{onSent: func(packet transportlog.PacketSent) {
		for _, frame := range packet.Frames {
			if _, ok := frame.Frame.(*transportlog.StreamsBlockedFrame); ok {
				once.Do(func() { close(blocked) })
			}
		}
	}}
	conn, _ := newConnPair(t, withClientRecorder(recorder), withServerBidiStreamLimit(-1))
	client := (&Transport{}).NewClientConn(conn)
	require.NoError(t, client.waitInitialSettings(t.Context()))
	result := make(chan error, 1)
	go func() {
		stream, err := client.OpenRequestStream(t.Context())
		if stream != nil {
			t.Error("a peer with zero credit cannot admit a request stream")
		}
		result <- err
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not wait for the peer's real stream credit")
	}

	client.rawConn.retireEarlyData()
	select {
	case err := <-result:
		require.ErrorIs(t, err, quic.Err0RTTRejected)
	case <-time.After(5 * time.Second):
		t.Fatal("a rejected generation retained its blocked stream opener")
	}

	require.Empty(t, client.rawConn.streams)
	require.NoError(t, context.Cause(conn.Context()))
}
