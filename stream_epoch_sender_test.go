package quic

import (
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"go.uber.org/mock/gomock"
)

func TestRetiredStreamEpochSuppressesPriorityAndCreditCallbacks(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	sender.EXPECT().recordStreamPriorityUpdated(protocol.StreamID(4), int8(2), true).Times(1)
	sender.EXPECT().onStreamCreditReleased(protocol.StreamID(4)).Times(1)
	sender.EXPECT().updateStreamPriority(protocol.StreamID(4)).Times(1)
	epoch := &streamEpochSender{streamSender: sender}
	epoch.recordStreamPriorityUpdated(4, 2, true)
	epoch.onStreamCreditReleased(4)
	epoch.updateStreamPriority(4)
	epoch.retire()
	// Stream IDs are reused after rejection. Late callbacks must not reach the
	// same ID's replacement stream or emit a fresh priority event for it.
	epoch.recordStreamPriorityUpdated(4, 1, false)
	epoch.onStreamCreditReleased(4)
	epoch.updateStreamPriority(4)
}
