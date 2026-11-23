package quic

import (
	"errors"
	"testing"
	"testing/synctest"

	"github.com/alvarorichard/enetx-quic-go/internal/ackhandler"
	"github.com/alvarorichard/enetx-quic-go/internal/handshake"
	"github.com/alvarorichard/enetx-quic-go/internal/mocks"
	mockackhandler "github.com/alvarorichard/enetx-quic-go/internal/mocks/ackhandler"
	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestConnectionLoopClosesFailedEarlySetupBeforePublishingReadiness(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		crypto := mocks.NewMockCryptoSetup(ctrl)
		handler := mockackhandler.NewMockSentPacketHandler(ctrl)
		sender := NewMockSender(ctrl)
		calls := 0
		conn := newClientTestConnection(t, ctrl, &Config{ClientHandshake: &ClientHandshake{
			FlushEarlyData: true, OnEarlyDataReady: func(*Conn) { calls++ },
		}}, true, connectionOptCryptoSetup(crypto), connectionOptSentPacketHandler(handler), connectionOptSender(sender))
		crypto.EXPECT().StartHandshake(gomock.Any()).Return(nil)
		gomock.InOrder(
			crypto.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventRestoredTransportParameters,
				TransportParameters: &wire.TransportParameters{ActiveConnectionIDLimit: 2, MaxUniStreamNum: 3, InitialMaxData: 4096}}),
			crypto.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		)
		crypto.EXPECT().Close().Return(nil)
		handler.EXPECT().GetLossDetectionTimeout().AnyTimes()
		handler.EXPECT().TimeUntilSend().AnyTimes()
		gomock.InOrder(
			handler.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone),
			handler.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendAny),
		)
		sender.EXPECT().Run().Return(nil)
		sender.EXPECT().WouldBlock().Return(false).AnyTimes()
		sender.EXPECT().Close()
		conn.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
		cause := errors.New("early setup packet could not be serialized")
		conn.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, cause)
		err := conn.conn.run()
		synctest.Wait() // The connection owns an asynchronously started send loop.
		require.ErrorContains(t, err, cause.Error())
		require.Equal(t, 1, calls)
		select {
		case <-conn.conn.earlyConnReadyChan:
			t.Fatal("a failed setup published an early connection")
		default:
		}
	})
}
