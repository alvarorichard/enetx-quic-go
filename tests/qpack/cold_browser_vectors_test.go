package qpack_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	codec "github.com/enetx/quic-go/internal/qpack"
	"github.com/stretchr/testify/require"
)

// The first native section has no preparation requests or prior dynamic entries.
// Only the first instruction prefix is compared: the retained native encoder
// stream also contains the following eleven requests and their feedback history.
func TestEncoderIndependentColdBrowserFirstSections(t *testing.T) {
	paths, err := filepath.Glob("testdata/cold/*.json")
	require.NoError(t, err)
	require.Len(t, paths, 8)
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			var fixture struct {
				Provenance   string               `json:"provenance"`
				Capacity     uint64               `json:"capacity"`
				Options      codec.EncoderOptions `json:"options"`
				CapacitySent bool                 `json:"send_capacity"`
				Encoder      string               `json:"whole_native_encoder_stream_hex"`
				First        struct {
					StreamID uint64        `json:"stream_id"`
					Fields   []codec.Field `json:"fields"`
					Block    string        `json:"header_block_hex"`
				} `json:"first_section"`
			}
			require.NoError(t, json.Unmarshal(data, &fixture))
			require.NotEmpty(t, fixture.Provenance)
			require.Zero(t, fixture.First.StreamID)
			e := configured(t, fixture.Options, fixture.Capacity, fixture.Capacity, 16)
			block, instructions := encode(t, e, 0, fixture.First.Fields...)
			want, err := hex.DecodeString(fixture.First.Block)
			require.NoError(t, err)
			require.Equal(t, want, block)
			if fixture.CapacitySent {
				instructions = append(codec.AppendEncoderCapacity(nil, fixture.Capacity), instructions...)
			}

			whole, err := hex.DecodeString(fixture.Encoder)
			require.NoError(t, err)
			require.True(t, bytes.HasPrefix(whole, instructions), "first instructions differ from the native encoder stream")
		})
	}
}
