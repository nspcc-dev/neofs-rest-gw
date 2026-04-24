package handlers

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// MockReadCloser is a mock implementation of readCloserWriterTo for testing purposes.
type MockReadCloserWriterTo struct {
	Data   []byte
	ReadAt int
	Err    error
	Closed bool
}

// Read implements the io.Reader interface.
func (m *MockReadCloserWriterTo) Read(p []byte) (int, error) {
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

func (m *MockReadCloserWriterTo) WriteTo(w io.Writer) (int64, error) {
	if m.Err != nil {
		return 0, m.Err
	}

	if m.ReadAt >= len(m.Data) {
		return 0, nil
	}

	n, err := w.Write(m.Data[m.ReadAt:])
	if err != nil {
		return 0, err
	}
	m.ReadAt += n
	return int64(n), nil
}

// Close implements the io.Closer interface.
func (m *MockReadCloserWriterTo) Close() error {
	m.Closed = true
	return nil
}

func TestRangeReaderMy_ReadAndWriteTo(t *testing.T) {
	tests := []struct {
		name               string
		payloadHead        []byte
		payload            []byte
		totalLength        uint64
		start              uint64
		length             uint64
		expected           []byte
		expectReadError    bool
		expectWriteToError bool
	}{
		{
			name:        "start after payloadHead and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      5,
			expected:    []byte{6, 7, 8, 9, 10},
		},
		{
			name:        "start after payloadHead and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      3,
			expected:    []byte{6, 7, 8},
		},
		{
			name:        "start after payloadHead and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       5,
			length:      6,
			expected:    []byte{6, 7, 8, 9, 10},
		},
		{
			name:        "start after payloadHead with gap and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      5,
			expected:    []byte{8, 9, 10},
		},
		{
			name:        "start after payloadHead with gap and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      2,
			expected:    []byte{8, 9},
		},
		{
			name:        "start after payloadHead with gap and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       7,
			length:      5,
			expected:    []byte{8, 9, 10},
		},
		{
			name:        "start within payloadHead and read to the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      8,
			expected:    []byte{3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:        "start within payloadHead and do not read until the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      5,
			expected:    []byte{3, 4, 5, 6, 7},
		},
		{
			name:        "start within payloadHead and read beyond the end",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       2,
			length:      10,
			expected:    []byte{3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:        "piece of payloadHead",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       1,
			length:      3,
			expected:    []byte{2, 3, 4},
		},
		{
			name:        "read full",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{6, 7, 8, 9, 10},
			totalLength: 10,
			start:       0,
			length:      10,
			expected:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name:        "empty payloadHead",
			payloadHead: []byte{},
			payload:     []byte{1, 2, 3, 4, 5},
			totalLength: 5,
			start:       0,
			length:      5,
			expected:    []byte{1, 2, 3, 4, 5},
		},
		{
			name:        "empty payload",
			payloadHead: []byte{1, 2, 3, 4, 5},
			payload:     []byte{},
			totalLength: 5,
			start:       0,
			length:      5,
			expected:    []byte{1, 2, 3, 4, 5},
		},
		{
			name:            "empty payloadHead and payload return error",
			payloadHead:     []byte{},
			payload:         []byte{},
			totalLength:     0,
			start:           0,
			length:          5,
			expected:        nil,
			expectReadError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &MockReadCloserWriterTo{Data: tt.payload}
			r := NewRangeReader(mock, tt.payloadHead, tt.totalLength, tt.start)

			buf := make([]byte, tt.length)
			n, err := r.Read(buf)
			if tt.expectReadError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, n, len(tt.expected))
				require.True(t, bytes.Equal(buf[:n], tt.expected))
			}

			writeToTotalLength := tt.start + uint64(len(tt.expected))
			payloadLen := int(writeToTotalLength - min(writeToTotalLength, uint64(len(tt.payloadHead))))
			mock = &MockReadCloserWriterTo{Data: tt.payload[:payloadLen]}
			r = NewRangeReader(mock, tt.payloadHead, writeToTotalLength, tt.start)
			var writeToBuf bytes.Buffer
			n64, err := r.WriteTo(&writeToBuf)
			if tt.expectWriteToError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Len(t, tt.expected, int(n64))
				require.Equal(t, tt.expected, writeToBuf.Bytes())
			}
		})
	}
}

func TestRangeReader_Close(t *testing.T) {
	mock := &MockReadCloserWriterTo{}
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
