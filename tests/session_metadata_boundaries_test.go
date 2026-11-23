package quic_test

import (
	"crypto/tls"
	"testing"

	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestSessionMetadataRejectsMissingNativeState(t *testing.T) {
	for _, ticket := range []*tls.ClientSessionState{nil, new(tls.ClientSessionState)} {
		metadata, ok := quic.ClientSessionMetadata(ticket)
		require.False(t, ok)
		require.Equal(t, quic.SessionMetadata{}, metadata)
		version, ok := quic.SessionVersion(ticket)
		require.False(t, ok)
		require.Zero(t, version)
	}
}
