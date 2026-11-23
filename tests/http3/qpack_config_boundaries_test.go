package http3_test

import (
	"math"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/http3"
	"github.com/alvarorichard/enetx-quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestQPACKConfigurationRejectsInvalidPolicyBeforeConnectionSetup(t *testing.T) {
	for name, config := range map[string]http3.QPACKConfig{
		"huffman":        {Huffman: 255},
		"indexing":       {Indexing: 255},
		"draining-nan":   {DrainingFraction: math.NaN()},
		"draining-low":   {DrainingFraction: -0.1},
		"draining-high":  {DrainingFraction: 1.1},
		"uppercase-name": {NeverIndex: []string{"X-Secret"}},
		"invalid-name":   {NeverIndex: []string{"bad\nname"}},
		"empty-name":     {NeverIndex: []string{""}},
		"unknown-stream": {StreamOrder: []http3.QPACKStreamType{4}},
		"duplicate-stream": {StreamOrder: []http3.QPACKStreamType{
			http3.QPACKEncoderStream, http3.QPACKDecoderStream, http3.QPACKEncoderStream,
		}},
		"capacity-overflow": {EncoderTableCapacity: quicvarint.Max + 1},
		"timing":            {EncoderCapacityTiming: 255},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, config.Validate())
		})
	}

	require.NoError(t, (*http3.QPACKConfig)(nil).Validate())
	require.NoError(t, (&http3.QPACKConfig{
		DrainingFraction: 1, NeverIndex: []string{":path", "authorization"},
		StreamOrder:          []http3.QPACKStreamType{http3.QPACKDecoderStream, http3.QPACKEncoderStream},
		EncoderTableCapacity: quicvarint.Max, EncoderCapacityTiming: http3.QPACKCapacityBeforeHeaders,
	}).Validate())
}
