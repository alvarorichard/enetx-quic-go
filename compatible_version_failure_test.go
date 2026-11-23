package quic

import (
	"bytes"
	"errors"
	"testing"

	"github.com/enetx/quic-go/internal/handshake"
	"github.com/enetx/quic-go/internal/mocks"
	"github.com/enetx/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type failingCompatibleSetup struct {
	cryptoStreamHandler
	compatible compatibleCryptoSetup
	cause      error
}

func (s failingCompatibleSetup) InitialOpenerForVersion(version protocol.Version) (handshake.LongHeaderOpener, error) {
	return s.compatible.InitialOpenerForVersion(version)
}

func (s failingCompatibleSetup) SwitchVersion(protocol.Version) error { return s.cause }

func TestCompatibleVersionFailureCannotCommitCandidateState(t *testing.T) {
	for _, stage := range []string{"unsupported-provider", "dropped-initial-keys", "switch-failed"} {
		t.Run(stage, func(t *testing.T) {
			conn := compatibleTestConn(t, protocol.Version1)
			header, data := compatibleInitialPacket(t, conn, protocol.Version2, conn.origDestConnID)
			before := bytes.Clone(data)
			switch stage {
			case "unsupported-provider":
				conn.cryptoStreamHandler = mocks.NewMockCryptoSetup(gomock.NewController(t))
			case "dropped-initial-keys":
				conn.cryptoStreamHandler.DiscardInitialKeys()
			case "switch-failed":
				conn.cryptoStreamHandler = failingCompatibleSetup{
					cryptoStreamHandler: conn.cryptoStreamHandler,
					compatible:          conn.cryptoStreamHandler.(compatibleCryptoSetup),
					cause:               errors.New("provider failed the compatible version switch"),
				}
			}

			require.False(t, conn.acceptCompatibleVersion(header, data))
			require.Equal(t, protocol.Version1, conn.version)
			require.False(t, conn.compatibleVersion.confirmed)
			require.Equal(t, before, data, "failed candidate authentication must leave the actual input packet intact")
		})
	}
}
