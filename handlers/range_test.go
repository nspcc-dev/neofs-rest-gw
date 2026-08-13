package handlers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRangeHeader(t *testing.T) {
	tests := []struct {
		name       string
		rangeParam string
		expected   httpRange
		wantErr    bool
	}{
		{
			name:       "valid bounds",
			rangeParam: "bytes=0-499",
			expected:   httpRange{kind: rangeBounds, first: 0, last: 499},
		},
		{
			name:       "valid bounds, single byte",
			rangeParam: "bytes=5-5",
			expected:   httpRange{kind: rangeBounds, first: 5, last: 5},
		},
		{
			name:       "valid open-ended range",
			rangeParam: "bytes=500-",
			expected:   httpRange{kind: rangeFrom, first: 500},
		},
		{
			name:       "valid suffix range",
			rangeParam: "bytes=-500",
			expected:   httpRange{kind: rangeSuffix, suffix: 500},
		},
		{
			name:       "unknown unit",
			rangeParam: "sweets=500-600",
			wantErr:    true,
		},
		{
			name:       "empty spec",
			rangeParam: "bytes=",
			wantErr:    true,
		},
		{
			name:       "dash only",
			rangeParam: "bytes=-",
			wantErr:    true,
		},
		{
			name:       "no dash",
			rangeParam: "bytes=500",
			wantErr:    true,
		},
		{
			name:       "extra dash",
			rangeParam: "bytes=1-2-3",
			wantErr:    true,
		},
		{
			name:       "not a number",
			rangeParam: "bytes=abc-def",
			wantErr:    true,
		},
		{
			name:       "last is not a number",
			rangeParam: "bytes=0-abc",
			wantErr:    true,
		},
		{
			name:       "first exceeds last",
			rangeParam: "bytes=500-300",
			wantErr:    true,
		},
		{
			name:       "multipart",
			rangeParam: "bytes=0-50, 100-150",
			wantErr:    true,
		},
		{
			name:       "zero suffix",
			rangeParam: "bytes=-0",
			wantErr:    true,
		},
		{
			name:       "first overflows uint64",
			rangeParam: "bytes=99999999999999999999-",
			wantErr:    true,
		},
		{
			name:       "negative first",
			rangeParam: "bytes=-5-10",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rng, err := parseRangeHeader(tt.rangeParam)
			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, rng)
		})
	}
}

func TestHTTPRangeResolve(t *testing.T) {
	tests := []struct {
		name        string
		rng         httpRange
		payloadSize uint64
		start       uint64
		end         uint64
		wantErr     bool
	}{
		{
			name:        "bounds within payload",
			rng:         httpRange{kind: rangeBounds, first: 0, last: 499},
			payloadSize: 1000,
			start:       0,
			end:         499,
		},
		{
			name:        "bounds last beyond payload is trimmed",
			rng:         httpRange{kind: rangeBounds, first: 500, last: 1500},
			payloadSize: 1000,
			start:       500,
			end:         999,
		},
		{
			name:        "bounds first beyond payload",
			rng:         httpRange{kind: rangeBounds, first: 1500, last: 1600},
			payloadSize: 1000,
			wantErr:     true,
		},
		{
			name:        "bounds first at payload size",
			rng:         httpRange{kind: rangeBounds, first: 1000, last: 1000},
			payloadSize: 1000,
			wantErr:     true,
		},
		{
			name:        "bounds of a single byte object",
			rng:         httpRange{kind: rangeBounds, first: 0, last: 0},
			payloadSize: 1,
			start:       0,
			end:         0,
		},
		{
			name:        "open-ended within payload",
			rng:         httpRange{kind: rangeFrom, first: 500},
			payloadSize: 1000,
			start:       500,
			end:         999,
		},
		{
			name:        "open-ended at payload size",
			rng:         httpRange{kind: rangeFrom, first: 1000},
			payloadSize: 1000,
			wantErr:     true,
		},
		{
			name:        "suffix within payload",
			rng:         httpRange{kind: rangeSuffix, suffix: 500},
			payloadSize: 1000,
			start:       500,
			end:         999,
		},
		{
			name:        "suffix equal to payload",
			rng:         httpRange{kind: rangeSuffix, suffix: 1000},
			payloadSize: 1000,
			start:       0,
			end:         999,
		},
		{
			name:        "suffix beyond payload returns the whole object",
			rng:         httpRange{kind: rangeSuffix, suffix: 1500},
			payloadSize: 1000,
			start:       0,
			end:         999,
		},
		{
			name:        "bounds of an empty object",
			rng:         httpRange{kind: rangeBounds, first: 0, last: 0},
			payloadSize: 0,
			wantErr:     true,
		},
		{
			name:        "open-ended for an empty object",
			rng:         httpRange{kind: rangeFrom, first: 0},
			payloadSize: 0,
			wantErr:     true,
		},
		{
			name:        "suffix for an empty object",
			rng:         httpRange{kind: rangeSuffix, suffix: 1},
			payloadSize: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := tt.rng.resolveRangeForResponse(tt.payloadSize)
			if tt.wantErr {
				require.ErrorIs(t, err, ErrRangeNotSatisfiable)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.start, start)
			require.Equal(t, tt.end, end)
		})
	}
}
