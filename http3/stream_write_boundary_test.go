package http3

import (
	"bytes"
	"io"
	"testing"

	"github.com/enetx/quic-go"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestChunkedDATAWriteReportsShortPayloadAndResumesItsFrame(t *testing.T) {
	conn, _ := newConnPair(t)
	stream := NewMockDatagramStream(gomock.NewController(t))
	stream.EXPECT().StreamID().Return(quic.StreamID(0)).AnyTimes()
	var wire bytes.Buffer
	gomock.InOrder(
		stream.EXPECT().Write([]byte{0, 4}).DoAndReturn(wire.Write),
		stream.EXPECT().Write([]byte("abcd")).DoAndReturn(func(data []byte) (int, error) {
			return wire.Write(data[:2])
		}),
		stream.EXPECT().Write([]byte("cd")).DoAndReturn(wire.Write),
		stream.EXPECT().Write([]byte{0, 2}).DoAndReturn(wire.Write),
		stream.EXPECT().Write([]byte("ef")).DoAndReturn(wire.Write),
		stream.EXPECT().Write([]byte{0, 2}).DoAndReturn(wire.Write),
		stream.EXPECT().Write([]byte("gh")).DoAndReturn(wire.Write),
	)
	framed := newStream(stream, newRawConn(conn, false, nil, nil, nil, nil), nil, nil, nil)
	framed.maxDataFrameSize = 4
	n, err := framed.Write([]byte("abcdefgh"))
	require.Equal(t, 2, n)
	require.ErrorIs(t, err, io.ErrShortWrite)
	require.True(t, framed.hasUnfinishedFrame())
	n, err = framed.Write([]byte("cdefgh"))
	require.Equal(t, 6, n)
	require.NoError(t, err)
	require.False(t, framed.hasUnfinishedFrame())
	require.Equal(t, []byte{0, 4, 'a', 'b', 'c', 'd', 0, 2, 'e', 'f', 0, 2, 'g', 'h'}, wire.Bytes(),
		"retrying the unaccepted suffix must complete the old DATA frame before creating another")
}
