package handlers

import (
	"errors"
	"io"
	"math"
)

// RangeReader allows reading data from both []byte `payloadHead` and readCloserWriterTo `payload`
// starting from position `start`, regardless of where the `start` is. Note that the first
// part of `payload` was read into `payloadHead`.
// RangeReader wraps an existing readCloserWriterTo `payload` to provide a specific byte range.
type RangeReader struct {
	payload     readCloseWriterTo
	payloadHead []byte
	totalLength uint64
	start       uint64
}

// NewRangeReader creates a new RangeReader for a given byte range.
func NewRangeReader(payload readCloseWriterTo, payloadHead []byte, totalLength uint64, start uint64) *RangeReader {
	return &RangeReader{
		payload:     payload,
		payloadHead: payloadHead,
		totalLength: totalLength,
		start:       start,
	}
}

// Read implements the io.Reader interface.
func (r *RangeReader) Read(p []byte) (int, error) {
	headLen := uint64(len(r.payloadHead))
	pLen := uint64(len(p))

	if headLen < r.start {
		// We have needless part after r.payloadHead that isn't requested.
		// Calculate needless totalLength of object - skipLen.
		skipLen := r.start - headLen
		// We need to read needless part and p or till the end of r.payload, which is (r.totalLength-headLen).
		readLen := min(skipLen+pLen, r.totalLength-headLen)
		buf := make([]byte, readLen)
		n, err := r.payload.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return n, err
		}
		// Copy bytes to p without needless part.
		n = copy(p, buf[skipLen:])
		return n, nil
	} else if headLen == r.start {
		// We have read bytes from the object exactly up to the beginning of the requested piece.
		return r.payload.Read(p)
	}
	// We have already read some of requested bytes in r.payloadHead.
	// The first part of p is in r.payloadHead, from the position r.start.
	n1 := uint64(copy(p, r.payloadHead[r.start:]))
	if n1 < pLen {
		// We need to read more.
		buf := make([]byte, pLen-n1)
		n2, err := r.payload.Read(buf)
		if err != nil && !errors.Is(err, io.EOF) {
			return n2, err
		}
		copy(p[n1:], buf[:n2])
		return int(n1) + n2, nil
	}
	return int(n1), nil
}

func (r *RangeReader) WriteTo(w io.Writer) (int64, error) {
	headLen := uint64(len(r.payloadHead))
	if r.start >= r.totalLength {
		return 0, nil
	}

	var written int64
	if r.start < headLen {
		headEnd := min(headLen, r.totalLength)
		n, err := w.Write(r.payloadHead[r.start:headEnd])
		written += int64(n)
		if err != nil {
			return written, err
		}
		if n != int(headEnd-r.start) {
			return written, io.ErrShortWrite
		}
		if headEnd == r.totalLength {
			return written, nil
		}
	} else if skipLen := r.start - headLen; skipLen > 0 {
		n, err := discard(r.payload, skipLen)
		if err != nil {
			return written, err
		}
		if n != skipLen {
			return written, nil
		}
	}

	n, err := r.payload.WriteTo(w)
	written += n
	return written, err
}

func discard(r io.Reader, n uint64) (uint64, error) {
	var discarded uint64
	for n > 0 {
		chunk := min(n, uint64(math.MaxInt64))
		nn, err := io.CopyN(io.Discard, r, int64(chunk))
		discarded += uint64(nn)
		n -= uint64(nn)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return discarded, nil
			}
			return discarded, err
		}
	}
	return discarded, nil
}

// Close implements the io.Closer interface.
func (r *RangeReader) Close() error {
	return r.payload.Close()
}
