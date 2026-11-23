//go:build windows

package quic_test

import (
	"testing"

	"github.com/alvarorichard/enetx-quic-go"
	"github.com/stretchr/testify/require"
)

func TestWindowsSocketCompatibilityConstants(t *testing.T) {
	// These public Winsock values were exposed before UDP internals moved.
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IP_DONTFRAGMENT.html
	// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Networking/WinSock/constant.IPV6_DONTFRAG.html
	require.EqualValues(t, 14, quic.IP_DONTFRAGMENT)
	require.EqualValues(t, 14, quic.IPV6_DONTFRAG)
}
