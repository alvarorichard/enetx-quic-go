package http3

import (
	"bytes"
	"encoding/hex"
	"testing"

	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func TestQPACKNeverIndexRewritesLongStaticReference(t *testing.T) {
	field := base.HeaderField{Name: "x-frame-options", Value: "sameorigin"}
	writer := newRequestWriter()
	writer.qpackConfig = &QPACKConfig{NeverIndex: []string{field.Name}}
	require.NoError(t, writer.writeQPACKField(":method", "GET"))
	prefix := bytes.Clone(writer.headerBuf.Bytes())
	require.NoError(t, writer.writeQPACKField(field.Name, field.Value))
	require.Equal(t, prefix, writer.headerBuf.Bytes()[:len(prefix)])
	require.Equal(t, []base.HeaderField{{Name: ":method", Value: "GET"}, field},
		decodeStaticQPACK(t, writer.headerBuf.Bytes()))
	require.EqualValues(t, 0x70, writer.headerBuf.Bytes()[len(prefix)]&0xf0)
}

func TestQPACKNeverIndexRejectsMalformedRepresentationsWithoutChangingPrefix(t *testing.T) {
	for name, field := range map[string][]byte{
		"missing-field":    nil,
		"truncated-index":  {0xff},
		"unfinished-index": {0xff, 0x80},
		"overflow-index":   {0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80},
		"dynamic-index":    {0x80},
	} {
		t.Run(name, func(t *testing.T) {
			prefix := []byte{0, 0, 0xd1}
			var buffer bytes.Buffer
			buffer.Write(prefix)
			buffer.Write(field)
			before := bytes.Clone(buffer.Bytes())
			require.Error(t, markQPACKFieldNeverIndexed(&buffer, len(prefix), "private"))
			require.Equal(t, before, buffer.Bytes(), "a rejected field must not corrupt earlier headers")
		})
	}
}

func TestQPACKPrefixedIntegerRFCVectors(t *testing.T) {
	// RFC 7541 Appendix C.1 uses the same prefixed-integer representation as
	// QPACK (RFC 9204 section 4.1.1), including continuation bytes.
	for _, tc := range []struct {
		name   string
		prefix uint8
		value  uint64
		wire   string
	}{
		{"small", 5, 10, "0a"},
		{"prefix-boundary", 5, 31, "1f00"},
		{"continuation", 5, 1337, "1f9a0a"},
		{"whole-byte", 8, 42, "2a"},
		{"huffman-length", 7, 128, "7f01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, err := hex.DecodeString(tc.wire)
			require.NoError(t, err)
			prefix := []byte{0xaa, 0xbb}
			require.Equal(t, append(prefix, expected...), appendQPACKInt(bytes.Clone(prefix), tc.prefix, 0, tc.value))
		})
	}
}
