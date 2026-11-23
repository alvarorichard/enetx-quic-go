package quic

import (
	"bytes"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/monotime"
	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/stretchr/testify/require"
)

func TestCreationSchedulingPreservesStreamBlockedNotification(t *testing.T) {
	for _, budget := range []protocol.ByteCount{53, 1200} {
		framer, control, request := creationTestStreams(t, 50)
		frames, streams, _ := framer.appendStreamFrames(nil, nil, budget, 1, protocol.Version1)
		require.NotEmpty(t, streams)
		require.Equal(t, control.StreamID(), streams[0].Frame.StreamID)
		require.Len(t, streams[0].Frame.Data, 50)
		if budget == 53 {
			require.Empty(t, frames, "a full packet defers the blocked notification")
			frames, _ = framer.AppendControlFrames(nil, 1200, monotime.Now(), protocol.Version1)
		}

		require.Len(t, frames, 1)
		require.Equal(t, &wire.StreamDataBlockedFrame{StreamID: control.StreamID(), MaximumStreamData: 50}, frames[0].Frame)
		control.updateSendWindow(4096)
		next := creationAppend(framer, 1200)
		require.NotEmpty(t, next)
		require.Equal(t, control.StreamID(), next[0].Frame.StreamID, "credit resumption retains the original creation order")
		for _, frame := range next {
			require.Contains(t, []StreamID{control.StreamID(), request.StreamID()}, frame.Frame.StreamID)
		}
	}
}

func TestCreationSchedulingPreservesConnectionBlockedNotification(t *testing.T) {
	for _, budget := range []protocol.ByteCount{50, 1200} {
		framer, control, request := creationTestStreams(t, 4096)
		require.NoError(t, control.TryWriteAll(bytes.Repeat([]byte("C"), 3996)))
		require.NoError(t, request.TryWriteAll(bytes.Repeat([]byte("R"), 3996)))
		frames, streams, _ := framer.appendStreamFrames(nil, nil, budget, 1, protocol.Version1)
		total := 0
		for _, frame := range streams {
			total += len(frame.Frame.Data)
		}

		if len(frames) == 0 {
			frames, _ = framer.AppendControlFrames(nil, 1200, monotime.Now(), protocol.Version1)
		}

		require.Len(t, frames, 1)
		require.Equal(t, &wire.DataBlockedFrame{MaximumData: 8192}, frames[0].Frame)
		for range 16 {
			frames := creationAppend(framer, 1200)
			if len(frames) == 0 {
				break
			}

			for _, frame := range frames {
				total += len(frame.Frame.Data)
			}
		}

		require.Equal(t, 8192, total)
		again, _, _ := framer.AppendStreamFrames(nil, nil, 1200, protocol.Version1)
		require.Empty(t, again, "the same exhausted connection window is reported once")
	}
}
