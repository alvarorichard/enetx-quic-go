package http3

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/alvarorichard/enetx-http"
	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

type earlyReplayBody struct {
	*strings.Reader
	closes int
}

func (b *earlyReplayBody) Close() error { b.closes++; return nil }

func TestEarlyReplayNormalizesMethodWithoutChangingOriginalRequest(t *testing.T) {
	for _, test := range []struct{ before, after string }{
		{MethodGet0RTT, http.MethodGet}, {MethodHead0RTT, http.MethodHead},
		{http.MethodPost, http.MethodPost}, {http.MethodPut, http.MethodPut},
	} {
		for _, empty := range []io.ReadCloser{nil, http.NoBody} {
			request, err := http.NewRequest(test.before, "https://localhost/resource", nil)
			require.NoError(t, err)
			request.Body = empty
			retry, reopened, err := requestAfterEarlyRejection(request, quic.Err0RTTRejected)
			require.NoError(t, err)
			require.False(t, reopened)
			require.NotSame(t, request, retry)
			require.Equal(t, test.after, retry.Method)
			require.Equal(t, test.before, request.Method)
			require.Equal(t, empty, retry.Body)
			require.Same(t, request.URL, retry.URL)
		}
	}
}

func TestEarlyReplayReopensOnlyAnAlreadyAttemptedBody(t *testing.T) {
	for _, mode := range []string{"unopened", "reopen", "missing-getbody", "getbody-error"} {
		t.Run(mode, func(t *testing.T) {
			original := &earlyReplayBody{Reader: strings.NewReader("payload")}
			fresh := &earlyReplayBody{Reader: strings.NewReader("payload")}
			request, err := http.NewRequest(http.MethodPost, "https://localhost/upload", original)
			require.NoError(t, err)
			cause := errors.New("request body cannot be reopened")
			calls := 0
			request.GetBody = func() (io.ReadCloser, error) {
				calls++
				if mode == "getbody-error" {
					return nil, cause
				}

				return fresh, nil
			}
			if mode == "missing-getbody" {
				request.GetBody = nil
			}

			var rejected error = quic.Err0RTTRejected
			if mode == "unopened" {
				rejected = &errConnUnusable{e: rejected}
			}

			retry, reopened, err := requestAfterEarlyRejection(request, rejected)
			switch mode {
			case "missing-getbody", "getbody-error":
				if mode == "missing-getbody" {
					require.ErrorIs(t, err, rejected)
					require.Zero(t, calls)
				} else {
					require.ErrorIs(t, err, cause)
					require.Equal(t, 1, calls)
				}

				require.Nil(t, retry)
				require.False(t, reopened)
			case "unopened":
				require.NoError(t, err)
				require.False(t, reopened)
				require.Zero(t, calls)
				require.Same(t, original, retry.Body)
			default:
				require.NoError(t, err)
				require.True(t, reopened)
				require.Equal(t, 1, calls)
				data, err := io.ReadAll(retry.Body)
				require.NoError(t, err)
				require.Equal(t, "payload", string(data))
				require.NoError(t, retry.Body.Close())
				require.NoError(t, retry.Body.Close())
				require.Equal(t, 1, fresh.closes, "retry ownership must close a reopened body once")
			}

			require.Same(t, original, request.Body)
			require.Zero(t, original.closes, "preparing a replay cannot close the original attempt's body")
		})
	}
}
