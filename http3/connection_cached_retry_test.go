package http3

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-http/httptest"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCachedRequestMayDialAfterPeerRejectsItsStartedAttempt(t *testing.T) {
	first, _ := newConnPair(t)
	second, _ := newConnPair(t)
	client := NewMockClientConn(gomock.NewController(t))
	dials := 0
	transport := &Transport{
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			dials++
			if dials == 1 {
				return first, nil
			}

			require.Equal(t, 2, dials, "a cache-only initial attempt permits at most one normal redial")
			return second, nil
		},
		newClientConn: func(*quic.Conn) clientConn { return client },
	}
	defer transport.Close()
	warm := httptest.NewRequest(http.MethodGet, "https://localhost/warm", nil)
	client.EXPECT().RoundTrip(warm).Return(&http.Response{Request: warm}, nil)
	_, err := transport.RoundTrip(warm)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "https://localhost/retry", nil)
	gomock.InOrder(
		client.EXPECT().RoundTrip(request).Return(nil, &Error{Remote: true, ErrorCode: ErrCodeRequestRejected}),
		client.EXPECT().RoundTrip(request).Return(&http.Response{Request: request}, nil),
	)
	response, err := transport.RoundTripCached(request)
	require.NoError(t, err)
	require.Same(t, request, response.Request)
	require.Equal(t, 2, dials)
	require.Len(t, transport.retired, 1, "the previous connection remains owned while older response bodies can still exist")
	require.NoError(t, second.Context().Err())
	transport.RetireConnections()
	require.Error(t, second.Context().Err())
	require.NoError(t, transport.Close())
	require.Error(t, first.Context().Err())
	require.Error(t, second.Context().Err())
}
