package handlers

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockReadCloser is a mock implementation of io.ReadCloser for testing purposes.
type MockReadCloser struct {
	Data   []byte
	ReadAt int
	Err    error
	Closed bool
}

// Read implements the io.Reader interface.
func (m *MockReadCloser) Read(p []byte) (int, error) {
	if m.Err != nil {
		return 0, m.Err
	}

	if m.ReadAt >= len(m.Data) {
		return 0, io.EOF
	}

	n := copy(p, m.Data[m.ReadAt:])
	m.ReadAt += n
	return n, nil
}

// Close implements the io.Closer interface.
func (m *MockReadCloser) Close() error {
	m.Closed = true
	return nil
}

func TestRangeReaderMy_Read(t *testing.T) {
	tests := []struct {
		name        string
		payloadHead []byte
		payload     []byte
		totalLength uint64
		start       uint64
		length      uint64
		expected    []byte
		expectError bool
	}{
		{
			name:        "start after payloadHead and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      5,
			expected:    []byte{6, 7, 8, 9, 10},
			expectError: false,
		},
		{
			name:        "start after payloadHead and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      3,
			expected:    []byte{6, 7, 8},
			expectError: false,
		},
		{
			name:        "start after payloadHead and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      6,
			expected:    []byte{6, 7, 8, 9, 10},
			expectError: false,
		},
		{
			name:        "start after payloadHead with gap and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      5,
			expected:    []byte{8, 9, 10},
			expectError: false,
		},
		{
			name:        "start after payloadHead with gap and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      2,
			expected:    []byte{8, 9},
			expectError: false,
		},
		{
			name:        "start after payloadHead with gap and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      5,
			expected:    []byte{8, 9, 10},
			expectError: false,
		},
		{
			name:        "start within payloadHead and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      8,
			expected:    []byte{3, 4, 5, 6, 7, 8, 9, 10},
			expectError: false,
		},
		{
			name:        "start within payloadHead and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      5,
			expected:    []byte{3, 4, 5, 6, 7},
			expectError: false,
		},
		{
			name:        "start within payloadHead and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      10,
			expected:    []byte{3, 4, 5, 6, 7, 8, 9, 10},
			expectError: false,
		},
		{
			name:        "piece of payloadHead",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       1,
			length:      3,
			expected:    []byte{2, 3, 4},
			expectError: false,
		},
		{
			name:        "read full",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       0,
			length:      10,
			expected:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			expectError: false,
		},
		{
			name:        "empty payloadHead",
			payloadHead: []byte{},
			payload:     []byte{1, 2, 3, 4, 5},
			totalLength: 5,
			start:       0,
			length:      5,
			expected:    []byte{1, 2, 3, 4, 5},
			expectError: false,
		},
		{
			name:        "empty payload",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{},
			totalLength: 5,
			start:       0,
			length:      5,
			expected:    []byte{1, 2, 3, 4, 5},
			expectError: false,
		},
		{
			name:        "empty payloadHead and payload return error",
			payloadHead: []byte{},
			payload:     []byte{},
			totalLength: 0,
			start:       0,
			length:      5,
			expected:    nil,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockReadCloser{Data: tt.payload}
			r := NewRangeReader(mock, tt.payloadHead, tt.totalLength, tt.start)

			buf := make([]byte, tt.length)
			n, err := r.Read(buf)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, n, len(tt.expected))
				require.True(t, bytes.Equal(buf[:n], tt.expected))
			}
		})
	}
}

func TestRangeReader_Close(t *testing.T) {
	mock := &MockReadCloser{}
	r := NewRangeReader(mock, nil, 0, 0)

	err := r.Close()
	require.NoError(t, err)
	require.True(t, mock.Closed)
}

func TestGetRangeParams(t *testing.T) {
	tests := []struct {
		name          string
		rangeParam    string
		payloadSize   uint64
		expectedStart uint64
		expectedEnd   uint64
		expectedError bool
	}{
		{
			name:          "beginning",
			rangeParam:    "bytes=0-499",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   499,
			expectedError: false,
		},
		{
			name:          "end",
			rangeParam:    "bytes=500-999",
			payloadSize:   1000,
			expectedStart: 500,
			expectedEnd:   999,
			expectedError: false,
		},
		{
			name:          "empty start",
			rangeParam:    "bytes=-500",
			payloadSize:   1000,
			expectedStart: 500,
			expectedEnd:   999,
			expectedError: false,
		},
		{
			name:          "empty end",
			rangeParam:    "bytes=500-",
			payloadSize:   1000,
			expectedStart: 500,
			expectedEnd:   999,
			expectedError: false,
		},
		{
			name:          "beyond payloadSize",
			rangeParam:    "bytes=500-1500",
			payloadSize:   1000,
			expectedStart: 500,
			expectedEnd:   999,
			expectedError: false,
		},
		{
			name:          "wrong prefix",
			rangeParam:    "sweets=500-600",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "out of payloadSize",
			rangeParam:    "bytes=1500-1600",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "wrong order",
			rangeParam:    "bytes=500-300",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "invalid",
			rangeParam:    "bytes=abc-def",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "empty",
			rangeParam:    "bytes=",
			payloadSize:   1000,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "zero payloadSize",
			rangeParam:    "bytes=0-",
			payloadSize:   0,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
		{
			name:          "multipart ranges",
			rangeParam:    "bytes=0-50, 100-150",
			payloadSize:   0,
			expectedStart: 0,
			expectedEnd:   0,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := getRangeParams(tt.rangeParam, tt.payloadSize)
			if tt.expectedError {
				require.Error(t, err, "Expected error but got none")
			} else {
				require.NoError(t, err, "Unexpected error: %v", err)
				require.Equal(t, tt.expectedStart, start, "Unexpected start value")
				require.Equal(t, tt.expectedEnd, end, "Unexpected end value")
			}
		})
	}
}
