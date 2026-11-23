package qpack_test

import (
	"bytes"
	"io"
	"testing"

	codec "github.com/alvarorichard/enetx-quic-go/internal/qpack"
	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestEncoderWithoutInstructionSinkDoesNotCommitInsertions(t *testing.T) {
	encoder := configured(t, codec.EncoderOptions{DynamicTable: true, Huffman: codec.HuffmanNever}, 128, 128, 1)
	fields := []codec.Field{{Name: "x-new", Value: "value"}}
	block, err := encoder.Encode(0, fields, nil)
	require.NoError(t, err)
	field, err := base.NewDecoder().Decode(block)()
	require.NoError(t, err)
	require.Equal(t, base.HeaderField{Name: "x-new", Value: "value"}, field)
	require.Equal(t, []byte{0, 0}, block[:2])

	block, instructions := encode(t, encoder, 4, fields...)
	// RFC 9204: the first committed insert has Required Insert Count 1,
	// represented as 2. No ghost entry may survive the missing sink.
	require.Equal(t, []byte{2, 0, 0x80}, block)
	require.Equal(t, []byte{0x45, 'x', '-', 'n', 'e', 'w', 5, 'v', 'a', 'l', 'u', 'e'}, instructions)
}

func TestEncoderRejectsInvalidOptionsBeforeCallingInstructionSink(t *testing.T) {
	for _, options := range []codec.EncoderOptions{{Huffman: 255}, {Indexing: 255}, {DrainingFraction: -1}} {
		encoder := codec.NewEncoder(options)
		block, err := encoder.Encode(0, []codec.Field{{Name: "x", Value: "value"}}, func([]byte) error {
			t.Fatal("invalid options cannot publish encoder instructions")
			return nil
		})
		require.Error(t, err)
		require.Nil(t, block)
	}
}

func TestNewNameIndexingDoesNotReferenceAnUnacknowledgedOtherStream(t *testing.T) {
	encoder := configured(t, codec.EncoderOptions{
		DynamicTable: true, Indexing: codec.IndexNewNames, Huffman: codec.HuffmanNever,
	}, 128, 128, 1)
	_, instructions := encode(t, encoder, 0, codec.Field{Name: "x-new", Value: "first"})
	require.NotEmpty(t, instructions)
	block, instructions := encode(t, encoder, 4, codec.Field{Name: "x-new", Value: "second"})
	require.Empty(t, instructions, "the one blocked-stream slot is already occupied")
	require.Equal(t, []byte{0, 0}, block[:2])
	field, err := base.NewDecoder().Decode(block)()
	require.NoError(t, err)
	require.Equal(t, base.HeaderField{Name: "x-new", Value: "second"}, field)

	feedback(t, encoder, 0x80)
	block, instructions = encode(t, encoder, 8, codec.Field{Name: "x-new", Value: "second"})
	require.Empty(t, instructions, "acknowledged names can be reused without inserting values")
	decoder := codec.NewDecoder(128, 1, nil)
	// RFC 9204: capacity 128, one literal-name insertion, followed by a
	// field section referring to that acknowledged name with a different value.
	wire := append(codec.AppendEncoderCapacity(nil, 128), []byte{0x45, 'x', '-', 'n', 'e', 'w', 5, 'f', 'i', 'r', 's', 't'}...)
	require.ErrorIs(t, decoder.ReadEncoder(bytes.NewReader(wire)), io.EOF)
	fields, err := decoder.Decode(t.Context(), 8, block, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x-new", Value: "second"}}, fields)
}

func TestEncoderLiteralUsesPostBaseNameInsertedInTheSameSection(t *testing.T) {
	encoder := configured(t, codec.EncoderOptions{
		DynamicTable: true, Indexing: codec.IndexNewNames, Huffman: codec.HuffmanNever, PostBaseReferences: true,
	}, 128, 128, 1)
	block, instructions := encode(t, encoder, 0,
		codec.Field{Name: "x", Value: "first"}, codec.Field{Name: "x", Value: "second"})
	// RFC 9204 sections 4.5.3 and 4.5.5: Base 0, inserted entry 0,
	// indexed post-base field followed by a literal post-base name reference.
	require.Equal(t, []byte{2, 0x80, 0x10, 0, 6, 's', 'e', 'c', 'o', 'n', 'd'}, block)
	decoder := codec.NewDecoder(128, 1, nil)
	wire := append(codec.AppendEncoderCapacity(nil, 128), instructions...)
	require.ErrorIs(t, decoder.ReadEncoder(bytes.NewReader(wire)), io.EOF)
	fields, err := decoder.Decode(t.Context(), 0, block, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x", Value: "first"}, {Name: "x", Value: "second"}}, fields)
}
