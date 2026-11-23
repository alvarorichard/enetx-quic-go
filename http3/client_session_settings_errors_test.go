package http3

import (
	"bytes"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/alvarorichard/enetx-quic-go"
	"github.com/alvarorichard/enetx-quic-go/tlsquic"
	"github.com/stretchr/testify/require"
)

func TestClientSettingsCacheRejectsEmptyTicketStateWithoutPanic(t *testing.T) {
	ticket := new(tls.ClientSessionState)
	_, ok := ClientSessionSettings(ticket)
	require.False(t, ok)
	session := &clientSettingsSession{cache: &settingsRecordingCache{ticket: ticket}}
	require.NotPanics(t, func() {
		got, ok := session.Get("application-cache-key")
		require.False(t, ok)
		require.Nil(t, got)
	})
	require.NotPanics(t, func() {
		copy, err := cloneClientTicket(ticket, nil, false)
		require.Error(t, err)
		require.Nil(t, copy)
	})
	require.NotPanics(t, func() {
		session.commitSettings(&settingsFrame{MaxFieldSectionSize: -1})
		session.Put("application-cache-key", ticket)
	})
	require.Empty(t, session.cache.(*settingsRecordingCache).puts, "invalid tickets must not replace cached state")
}

func TestClientSettingsCacheRejectsUnusableAndOversizedSerializedState(t *testing.T) {
	for _, name := range []string{"invalid-session", "oversized-extra"} {
		t.Run(name, func(t *testing.T) {
			state := new(tls.SessionState)
			if name == "oversized-extra" {
				// TLS uses a uint24 for Extra and for every item it contains.
				state.Extra = [][]byte{bytes.Repeat([]byte{1}, 1<<24)}
			}

			ticket, err := tls.NewResumptionState([]byte("opaque"), state)
			require.NoError(t, err)
			copy, err := cloneClientTicket(ticket, nil, false)
			require.Error(t, err)
			require.Nil(t, copy)
			if name == "invalid-session" {
				require.ErrorContains(t, err, "invalid session encoding")
			} else {
				require.ErrorContains(t, err, "cryptobyte:")
			}

			base := &settingsRecordingCache{ticket: ticket}
			session := &clientSettingsSession{cache: base}
			copy, ok := session.Get("opaque-key")
			require.False(t, ok)
			require.Nil(t, copy)
			require.Same(t, ticket, base.ticket, "rejecting a snapshot must not mutate the application's cache")
		})
	}
}

func TestClientSettingsMetadataRejectsIncompleteLengthVarint(t *testing.T) {
	for _, frame := range [][]byte{{4, 0x40}, {0x40}, {0, 0}} {
		data := append([]byte(clientSettingsPrefix), frame...)
		saved, ok := clientSettingsFromExtra([][]byte{data})
		require.False(t, ok)
		require.Nil(t, saved)
	}
}

func TestTLSFactoryDecorationRejectsFailuresWithoutPublishingSession(t *testing.T) {
	conn, _ := newConnPair(t)
	for _, mode := range []string{"nil-factory", "factory-error", "nil-provider"} {
		t.Run(mode, func(t *testing.T) {
			transport := new(Transport)
			cause := errors.New("application TLS factory failed")
			calls := 0
			original := &tls.Config{ClientSessionCache: tls.NewLRUClientSessionCache(1)}
			cache := original.ClientSessionCache
			factory := func(config *tls.Config) (tlsquic.Conn, error) {
				calls++
				require.NotSame(t, original, config)
				require.IsType(t, &clientSettingsSession{}, config.ClientSessionCache)
				if mode == "factory-error" {
					return nil, cause
				}

				return nil, nil
			}
			decoratorCalls := 0
			decorated := transport.wrapSessionTLS(func(actual *quic.Conn, next tlsquic.NewClient) tlsquic.NewClient {
				decoratorCalls++
				require.Same(t, conn, actual)
				if mode == "nil-factory" {
					return nil
				}

				return next
			})(conn, factory)
			provider, err := decorated(original)
			require.Nil(t, provider)
			switch mode {
			case "nil-factory":
				require.ErrorContains(t, err, "decorator returned nil")
				require.Zero(t, calls)
			case "factory-error":
				require.ErrorIs(t, err, cause)
				require.Equal(t, 1, calls)
			default:
				require.NoError(t, err)
				require.Equal(t, 1, calls)
			}

			require.Equal(t, 1, decoratorCalls)
			require.Same(t, cache, original.ClientSessionCache)
			_, published := transport.clientSessions.Load(conn)
			require.False(t, published)
		})
	}
}
