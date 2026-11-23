package qpack

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	base "github.com/quic-go/qpack"
	"github.com/stretchr/testify/require"
)

func decoderWithOneEntry(t *testing.T, emit func([]byte) error) *Decoder {
	t.Helper()
	decoder := NewDecoder(128, 1, emit)
	wire := AppendEncoderCapacity(nil, 128)
	wire = append(wire, 0x41, 'x', 0x01, 'y') // Insert With Literal Name: x=y.
	require.ErrorIs(t, decoder.ReadEncoder(bytes.NewReader(wire)), io.EOF)
	return decoder
}

func TestDecoderRequiredCountAndBaseArithmeticBoundaries(t *testing.T) {
	for name, block := range map[string][]byte{
		"zero-required-from-nonzero-encoding": {1, 0},
		"first-wrap-exceeds-insertion-range":  {8, 0},
		"post-base-overflow":                  append(appendInt([]byte{0}, 7, 0, maxInt), 0x11),
	} {
		t.Run(name, func(t *testing.T) {
			fields, err := NewDecoder(128, 1, nil).Decode(t.Context(), 0, block, 1024, nil)
			require.ErrorIs(t, err, ErrDecompression)
			require.Nil(t, fields)
		})
	}

	decoder := decoderWithOneEntry(t, nil)
	block := appendInt([]byte{2}, 7, 0, maxInt) // Required=1 plus Delta Base overflows.
	fields, err := decoder.Decode(t.Context(), 0, block, 1024, nil)
	require.ErrorIs(t, err, ErrDecompression)
	require.Nil(t, fields)
}

func TestDecoderReferenceCountMustDescribeActuallyUsedEntries(t *testing.T) {
	for name, block := range map[string][]byte{
		"reference-above-required": {0, 1, 0x80},
		"unused-required-entry":    {2, 0},
	} {
		t.Run(name, func(t *testing.T) {
			fields, err := decoderWithOneEntry(t, nil).Decode(t.Context(), 0, block, 1024, nil)
			require.ErrorIs(t, err, ErrDecompression)
			require.Nil(t, fields)
		})
	}
}

func TestDecoderPostBaseNameReferenceAndFieldBudget(t *testing.T) {
	decoder := decoderWithOneEntry(t, nil)
	// Required=1, negative Delta Base=0 gives Base=0. The literal refers to
	// post-base entry zero's name and supplies a new value, x=z.
	fields, err := decoder.Decode(t.Context(), 0, []byte{2, 0x80, 0, 1, 'z'}, 1024, nil)
	require.NoError(t, err)
	require.Equal(t, []base.HeaderField{{Name: "x", Value: "z"}}, fields)

	fields, err = decoder.Decode(t.Context(), 4, []byte{0, 0, 0x21, 'x', 2, 'y', 'z'}, 1, nil)
	require.ErrorIs(t, err, ErrFieldSectionTooLarge)
	require.Nil(t, fields)
}

func TestDecoderBlockedWaitErrorReleasesStreamAllowance(t *testing.T) {
	decoder := NewDecoder(128, 1, nil)
	sentinel := errors.New("request read deadline")
	for _, stream := range []uint64{0, 4} {
		calls := 0
		fields, err := decoder.Decode(t.Context(), stream, []byte{2, 0, 0x80}, 1024,
			func(ctx context.Context, changed <-chan struct{}) error {
				calls++
				require.NotNil(t, changed)
				require.NoError(t, ctx.Err())
				return sentinel
			})
		require.ErrorIs(t, err, sentinel)
		require.Nil(t, fields)
		require.Equal(t, 1, calls, "a previous failed wait retained the blocked-stream allowance")
	}
}

func TestDecoderAcknowledgementFailureClosesSubsequentDecodes(t *testing.T) {
	sentinel := errors.New("decoder feedback queue closed")
	calls := 0
	decoder := decoderWithOneEntry(t, func(instruction []byte) error {
		calls++
		if calls == 1 {
			require.Equal(t, []byte{1}, instruction) // Insert Count Increment.
			return nil
		}

		require.Equal(t, []byte{0x80}, instruction) // Section Acknowledgement, stream 0.
		return sentinel
	})
	fields, err := decoder.Decode(t.Context(), 0, []byte{2, 0, 0x80}, 1024, nil)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, fields)
	require.Equal(t, 2, calls)
	require.ErrorIs(t, decoder.Cancel(4), sentinel)
	fields, err = decoder.Decode(t.Context(), 4, []byte{0, 0}, 1024, nil)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, fields)
	require.Equal(t, 2, calls, "closed feedback must not be retried")
}

func TestDefaultBlockedDecoderWaitHonorsContextAndReleasesAllowance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		decoder := NewDecoder(128, 1, nil)
		for _, stream := range []uint64{0, 4} {
			ctx, cancel := context.WithCancelCause(t.Context())
			cause := errors.New("request canceled while waiting for encoder instructions")
			done := make(chan error, 1)
			go func() {
				fields, err := decoder.Decode(ctx, stream, []byte{2, 0, 0x80}, 1024, nil)
				if fields != nil {
					t.Error("cancellation cannot publish fields before their dynamic insertion arrives")
				}
				done <- err
			}()
			synctest.Wait()
			cancel(cause)
			require.ErrorIs(t, <-done, cause)
			require.Empty(t, decoder.blocked, "a canceled request must release the single blocked-stream slot")
		}
	})
}
