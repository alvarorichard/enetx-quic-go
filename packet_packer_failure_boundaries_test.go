package quic

import (
	"errors"
	"fmt"
	"testing"

	"github.com/enetx/quic-go/internal/ackhandler"
	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/monotime"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestCoalescedPacketPreservesSealingManagerFailure(t *testing.T) {
	for _, level := range []protocol.EncryptionLevel{
		protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT,
	} {
		t.Run(level.String(), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			packer := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			cause := errors.New("encryption keys failed")
			keyError := func(actual protocol.EncryptionLevel) error {
				if actual == level {
					return cause
				}

				return handshake.ErrKeysNotYetAvailable
			}
			if level == protocol.EncryptionInitial {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(nil, cause)
			} else {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
				packer.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, keyError(protocol.EncryptionHandshake)).AnyTimes()
				packer.sealingManager.EXPECT().Get1RTTSealer().Return(nil, keyError(protocol.Encryption1RTT)).AnyTimes()
				packer.sealingManager.EXPECT().Get0RTTSealer().Return(nil, keyError(protocol.Encryption0RTT)).AnyTimes()
			}

			packet, err := packer.packer.PackCoalescedPacket(false, 1200, monotime.Now(), protocol.Version1)
			require.Nil(t, packet, "a sealing failure must never publish a partially prepared datagram")
			require.ErrorIs(t, err, cause)
		})
	}
}

func TestCoalescedPacketRejectsInconsistentReservedPacketNumbers(t *testing.T) {
	for _, space := range []protocol.PacketNumberSpace{
		protocol.PacketNumberSpaceInitial, protocol.PacketNumberSpaceHandshake, protocol.PacketNumberSpaceAppData,
	} {
		t.Run(fmt.Sprint(space), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			packer := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			sealer := newMockShortHeaderSealer(ctrl)
			if space == protocol.PacketNumberSpaceInitial {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(sealer, nil)
			} else {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
			}

			if space == protocol.PacketNumberSpaceHandshake {
				packer.sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
			} else if space == protocol.PacketNumberSpaceAppData {
				packer.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped)
				packer.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable)
				packer.sealingManager.EXPECT().Get0RTTSealer().Return(sealer, nil)
				packer.framer.EXPECT().HasData().Return(false)
			}

			var force [3]bool
			force[space] = true
			packer.packer.ptoProbeForce = &force
			packer.pnManager.EXPECT().PeekPacketNumber(space).Return(protocol.PacketNumber(10), protocol.PacketNumberLen1)
			packer.pnManager.EXPECT().PopPacketNumber(space).Return(protocol.PacketNumber(11))
			packer.ackFramer.EXPECT().GetAckFrame(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			packet, err := packer.packer.PackCoalescedPacket(false, 1200, monotime.Now(), protocol.Version1)
			require.Nil(t, packet)
			require.ErrorContains(t, err, "expected 10, got 11")
		})
	}
}

type failingPacketFrame struct{ cause error }

func (f failingPacketFrame) Length(protocol.Version) protocol.ByteCount { return 1 }
func (f failingPacketFrame) Append([]byte, protocol.Version) ([]byte, error) {
	return nil, f.cause
}

func TestCoalescedPacketDoesNotPublishFailedFrameEncoding(t *testing.T) {
	for _, level := range []protocol.EncryptionLevel{
		protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT,
	} {
		t.Run(level.String(), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			packer := newTestPacketPacker(t, ctrl, protocol.PerspectiveClient)
			cause := errors.New("frame encoding failed")
			frame := failingPacketFrame{cause}
			sealer := newMockShortHeaderSealer(ctrl)
			if level == protocol.EncryptionInitial {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(sealer, nil)
				packer.retransmissionQueue.addInitial(frame)
			} else {
				packer.sealingManager.EXPECT().GetInitialSealer().Return(nil, handshake.ErrKeysDropped)
			}

			if level == protocol.EncryptionHandshake {
				packer.sealingManager.EXPECT().GetHandshakeSealer().Return(sealer, nil)
				packer.retransmissionQueue.addHandshake(frame)
			} else {
				packer.sealingManager.EXPECT().GetHandshakeSealer().Return(nil, handshake.ErrKeysDropped).AnyTimes()
			}

			if level == protocol.Encryption1RTT {
				packer.sealingManager.EXPECT().Get1RTTSealer().Return(sealer, nil)
			} else {
				packer.sealingManager.EXPECT().Get1RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
				if level == protocol.Encryption0RTT {
					packer.sealingManager.EXPECT().Get0RTTSealer().Return(sealer, nil)
				} else {
					packer.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysNotYetAvailable).AnyTimes()
				}
			}

			application := level == protocol.Encryption0RTT || level == protocol.Encryption1RTT
			packer.framer.EXPECT().HasData().Return(application).AnyTimes()
			if application {
				packer.framer.EXPECT().AppendControlFrames(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(
					[]ackhandler.Frame{{Frame: frame}}, protocol.ByteCount(1))
				packer.framer.EXPECT().AppendStreamFrames(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
					func(frames []ackhandler.Frame, streams []ackhandler.StreamFrame, _ protocol.ByteCount, _ protocol.Version) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
						return frames, streams, 0
					})
			}

			packer.pnManager.EXPECT().PeekPacketNumber(gomock.Any()).Return(protocol.PacketNumber(10), protocol.PacketNumberLen1).AnyTimes()
			packer.pnManager.EXPECT().PopPacketNumber(gomock.Any()).Return(protocol.PacketNumber(10)).AnyTimes()
			packer.ackFramer.EXPECT().GetAckFrame(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			packet, err := packer.packer.PackCoalescedPacket(false, 1200, monotime.Now(), protocol.Version1)
			require.Nil(t, packet)
			require.ErrorIs(t, err, cause)
		})
	}
}
