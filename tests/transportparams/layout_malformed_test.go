package transportparams_test

import (
	"bytes"
	"testing"

	"github.com/alvarorichard/enetx-quic-go/transportparams"
	"github.com/stretchr/testify/require"
)

func TestLayoutRejectsMalformedEncodedParametersWithoutMutatingInput(t *testing.T) {
	for name, test := range map[string]struct {
		wire  []byte
		panic string
	}{
		"truncated-id":     {wire: []byte{0x40}, panic: "transportparams: invalid engine parameter ID"},
		"missing-length":   {wire: []byte{4}, panic: "transportparams: invalid engine parameter length"},
		"truncated-length": {wire: []byte{4, 0x40}, panic: "transportparams: invalid engine parameter length"},
		"truncated-value":  {wire: []byte{4, 2, 1}, panic: "transportparams: invalid engine parameter length"},
	} {
		t.Run(name, func(t *testing.T) {
			original := bytes.Clone(test.wire)
			require.PanicsWithValue(t, test.panic, func() { (&transportparams.Layout{}).Apply(test.wire) })
			require.Equal(t, original, test.wire)
		})
	}
}
