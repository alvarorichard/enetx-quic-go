package quic

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestReadReadyCancellationWhileAnotherReaderOwnsStream(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	stream := newReceiveStream(0, sender, newTestStreamFlowController(0))
	stream.readOnce <- struct{}{}
	defer func() { <-stream.readOnce }()
	ctx, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("waiting reader abandoned")
	cancel(cause)

	require.ErrorIs(t, stream.WaitForReadReady(ctx, make(chan struct{})), cause)
	require.Len(t, stream.readOnce, 1, "a canceled waiter must not release another reader's ownership")
}

func TestReadReadyDeadlineAndBidirectionalForwarding(t *testing.T) {
	for _, mode := range []string{"expired", "timer", "ready-before-deadline"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				sender := NewMockStreamSender(gomock.NewController(t))
				receive := newReceiveStream(0, sender, newTestStreamFlowController(0))
				stream := &Stream{receiveStr: receive}
				ready := make(chan struct{})
				deadline := time.Now().Add(time.Second)
				if mode == "expired" {
					deadline = time.Now().Add(-time.Second)
				}

				require.NoError(t, receive.SetReadDeadline(deadline))
				done := make(chan error, 1)
				go func() { done <- stream.WaitForReadReady(t.Context(), ready) }()
				synctest.Wait()
				if mode == "ready-before-deadline" {
					close(ready)
				}

				err := <-done
				if mode == "ready-before-deadline" {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, os.ErrDeadlineExceeded)
				}

				require.Empty(t, receive.readOnce, "every completed wait releases read ownership")
			})
		})
	}
}
