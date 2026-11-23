package qpack

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

func TestPrefixedIntegerWireBoundaries(t *testing.T) {
	for _, value := range []uint64{0, 30, 31, 32, 127, 128, 1337, maxInt} {
		wire := appendInt(nil, 5, 0x20, value)
		got, err := readInt(bytes.NewReader(wire[1:]), wire[0], 5)
		require.NoError(t, err)
		require.Equal(t, value, got)
		require.EqualValues(t, 0x20, wire[0]&0xe0)
	}

	for name, wire := range map[string][]byte{
		"truncated": {31},
		"overflow":  append([]byte{31}, bytes.Repeat([]byte{255}, 9)...),
		"overlong":  append([]byte{31}, bytes.Repeat([]byte{128}, 9)...),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readInt(bytes.NewReader(wire[1:]), wire[0], 5)
			if name == "truncated" {
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			} else {
				require.ErrorIs(t, err, ErrDecompression)
			}
		})
	}
}

func TestStringDecoderBoundsAndMalformedWire(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wire    []byte
		limit   uint64
		huffman bool
		want    error
	}{
		{"length-truncated", []byte{127}, 100, false, io.ErrUnexpectedEOF},
		{"encoded-limit", []byte{3, 'a', 'b', 'c'}, 2, false, ErrFieldSectionTooLarge},
		{"payload-truncated", []byte{3, 'a'}, 3, false, io.ErrUnexpectedEOF},
		{"huffman-expansion", append([]byte{2}, hpack.AppendHuffmanString(nil, "aaa")...), 2, true, ErrFieldSectionTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := readString(bytes.NewReader(tc.wire[1:]), tc.wire[0], 7, tc.huffman, tc.limit)
			require.ErrorIs(t, err, tc.want)
			require.Empty(t, value)
		})
	}

	// A large decoded budget must saturate the encoded bound without overflow.
	wire := hpack.AppendHuffmanString(nil, "a")
	value, err := readString(bytes.NewReader(wire), byte(len(wire)), 7, true, maxInt)
	require.NoError(t, err)
	require.Equal(t, "a", value)

	_, err = readString(bytes.NewReader([]byte{255}), 1, 7, true, 10)
	require.Error(t, err, "invalid Huffman EOS/padding must fail")
}

func TestDecoderRejectsMalformedEncoderInstructions(t *testing.T) {
	for name, wire := range map[string]string{
		"missing-name-index":         "ff",
		"missing-literal-name":       "4178",
		"missing-literal-value":      "417801",
		"missing-static-value":       "c0",
		"invalid-static-index":       "ffff00",
		"dynamic-name-before-insert": "8000",
		"duplicate-before-insert":    "00",
		"capacity-above-budget":      "3fe207",
	} {
		t.Run(name, func(t *testing.T) {
			input, err := hex.DecodeString(wire)
			require.NoError(t, err)
			decoder := NewDecoder(128, 1, nil)
			err = decoder.ReadEncoder(bytes.NewReader(input))
			require.ErrorIs(t, err, ErrEncoderStream)
		})
	}
}

func TestDecoderRejectsMalformedFieldSections(t *testing.T) {
	for name, wire := range map[string]string{
		"no-required-insert-count":     "",
		"truncated-required":           "ff",
		"no-delta-base":                "00",
		"truncated-delta":              "007f",
		"unavailable-table":            "0200",
		"negative-zero-base":           "0080",
		"truncated-name-index":         "00005f",
		"missing-static-value":         "000050",
		"truncated-literal-name":       "000027",
		"missing-literal-value":        "00002178",
		"post-base-before-insert":      "000010",
		"post-base-name-before-insert": "000000",
	} {
		t.Run(name, func(t *testing.T) {
			input, err := hex.DecodeString(wire)
			require.NoError(t, err)
			decoder := NewDecoder(0, 0, nil)
			fields, err := decoder.Decode(t.Context(), 0, input, 1024, nil)
			require.ErrorIs(t, err, ErrDecompression)
			require.Nil(t, fields)
		})
	}
}

func TestDecoderCloseStopsEncoderFeedbackAndCancellation(t *testing.T) {
	sentinel := errors.New("connection retired")
	decoder := NewDecoder(128, 1, nil)
	decoder.Close(sentinel)
	// An accepted capacity instruction followed by a literal insertion must
	// preserve the original connection cause and never publish new feedback.
	err := decoder.ReadEncoder(bytes.NewReader([]byte{0x3f, 0x61, 0x41, 'x', 0x01, 'y'}))
	require.ErrorIs(t, err, sentinel)
	require.ErrorIs(t, decoder.Cancel(0), sentinel)
	fields, err := decoder.Decode(t.Context(), 0, []byte{0, 0}, 128, nil)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, fields)

	ctx, cancel := context.WithCancelCause(t.Context())
	cancel(sentinel)
	fields, err = NewDecoder(0, 0, nil).Decode(ctx, 0, []byte{0, 0}, 128, nil)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, fields)
}
