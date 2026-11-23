package simnet

import (
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExplicitStartPreservesEndpointTrafficAndLatency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		network := &Simnet{Router: &PerfectRouter{}}
		defer network.Close()
		settings := NodeBiDiLinkSettings{Latency: 10 * time.Millisecond}
		a := network.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 8000}, settings)
		b := network.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 8000}, settings)

		for _, explicit := range []bool{false, true, true} {
			if explicit {
				require.NoError(t, network.Start())
			}

			start := time.Now()
			_, err := a.WriteTo([]byte("request"), b.LocalAddr())
			require.NoError(t, err)
			var buffer [32]byte
			n, sender, err := b.ReadFrom(buffer[:])
			require.NoError(t, err)
			require.Equal(t, "request", string(buffer[:n]))
			require.Equal(t, a.LocalAddr().String(), sender.String())
			require.Equal(t, settings.Latency, time.Since(start), "explicit startup must not create a second link worker")

			_, err = b.WriteTo([]byte("reply"), sender)
			require.NoError(t, err)
			n, _, err = a.ReadFrom(buffer[:])
			require.NoError(t, err)
			require.Equal(t, "reply", string(buffer[:n]))
		}
	})
}
