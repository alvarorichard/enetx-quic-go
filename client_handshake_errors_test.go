package quic

import (
	"crypto/tls"
	"errors"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/internal/protocol"
	"github.com/alvarorichard/enetx-quic-go/internal/wire"
	"github.com/alvarorichard/enetx-quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

func TestClientHandshakeParameterFailureReachesTLSFactory(t *testing.T) {
	factoryFailure := errors.New("transport parameter entropy failed")
	for _, invalidLayout := range []bool{false, true} {
		t.Run(map[bool]string{false: "factory-error", true: "layout-error"}[invalidLayout], func(t *testing.T) {
			calls := 0
			config := &Config{ClientHandshake: &ClientHandshake{
				NewTransportParameters: func(version Version) (*transportparams.Layout, error) {
					calls++
					require.Equal(t, Version1, version)
					if invalidLayout {
						return &transportparams.Layout{Order: []uint64{4, 4}}, nil
					}

					return nil, factoryFailure
				},
			}}
			conn := &Conn{config: config, version: Version1}
			params := new(wire.TransportParameters)
			factory := conn.configureClientHandshake(params)
			require.NotNil(t, factory)

			provider, err := factory(&tls.Config{})
			require.Nil(t, provider)
			if invalidLayout {
				require.ErrorContains(t, err, "duplicate transport parameter")
			} else {
				require.ErrorIs(t, err, factoryFailure)
			}

			require.Equal(t, 1, calls, "TLS construction must not rerun the parameter factory")
			require.Nil(t, params.ClientLayout, "invalid state must not become the wire layout")
		})
	}
}

func TestClientHandshakeVersionInformationFailureReachesTLSFactory(t *testing.T) {
	conn := &Conn{
		config:  &Config{ClientHandshake: &ClientHandshake{CompatibleVersionNegotiation: true}},
		version: Version(0x12345678),
	}
	factory := conn.configureClientHandshake(new(wire.TransportParameters))
	require.NotNil(t, factory)
	provider, err := factory(&tls.Config{})
	require.Nil(t, provider)
	require.Error(t, err)
}

func TestCryptoRecoveryWithoutStreamOwnerIsEmpty(t *testing.T) {
	conn := new(Conn)
	for _, level := range []protocol.EncryptionLevel{
		protocol.EncryptionInitial, protocol.EncryptionHandshake,
		protocol.Encryption0RTT, protocol.Encryption1RTT,
	} {
		require.Nil(t, conn.cryptoRecovery(level))
	}
}
