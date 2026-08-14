package handlers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type (
	// rangeKind describes the form of a single HTTP byte range specifier.
	rangeKind uint8

	httpRange struct {
		kind   rangeKind
		first  uint64 // rangeBounds, rangeFrom.
		last   uint64 // rangeBounds.
		suffix uint64 // rangeSuffix.
	}
)

const (
	rangeBounds rangeKind = iota // bytes=first-last
	rangeFrom                    // bytes=first-
	rangeSuffix                  // bytes=-length
)

const (
	prefix  = "bytes="
	base    = 10
	bitSize = 64
)

var (
	// ErrRangeNotSatisfiable is returned when a valid range can not be applied to the object.
	ErrRangeNotSatisfiable = errors.New("range is not satisfiable")
)

func parseRangeHeader(rangeParam string) (httpRange, error) {
	spec, found := strings.CutPrefix(rangeParam, prefix)
	if !found {
		return httpRange{}, errors.New("bytes= prefix required")
	}

	if strings.Contains(spec, ",") {
		return httpRange{}, errors.New("unsupported multipart range request")
	}

	firstStr, lastStr, found := strings.Cut(spec, "-")
	if !found || strings.Contains(lastStr, "-") {
		return httpRange{}, errors.New("wrong Range header format")
	}

	if firstStr == "" && lastStr == "" {
		return httpRange{}, errors.New("wrong Range header format")
	}

	switch {
	case firstStr == "": // bytes=-length
		suffix, err := strconv.ParseUint(lastStr, base, bitSize)
		if err != nil {
			return httpRange{}, fmt.Errorf("invalid suffix length: %w", err)
		}

		if suffix == 0 {
			return httpRange{}, errors.New("zero suffix length")
		}

		return httpRange{kind: rangeSuffix, suffix: suffix}, nil
	case lastStr == "": // bytes=first-
		first, err := strconv.ParseUint(firstStr, base, bitSize)
		if err != nil {
			return httpRange{}, fmt.Errorf("invalid first byte position: %w", err)
		}

		return httpRange{kind: rangeFrom, first: first}, nil
	default: // bytes=first-last
		first, err := strconv.ParseUint(firstStr, base, bitSize)
		if err != nil {
			return httpRange{}, fmt.Errorf("invalid first byte position: %w", err)
		}

		last, err := strconv.ParseUint(lastStr, base, bitSize)
		if err != nil {
			return httpRange{}, fmt.Errorf("invalid last byte position: %w", err)
		}

		if first > last {
			return httpRange{}, errors.New("first byte position exceeds the last one")
		}

		return httpRange{kind: rangeBounds, first: first, last: last}, nil
	}
}

func (r httpRange) resolveRangeForResponse(payloadSize uint64) (uint64, uint64, error) {
	if payloadSize == 0 {
		return 0, 0, fmt.Errorf("%w: zero payload size", ErrRangeNotSatisfiable)
	}

	switch r.kind {
	case rangeSuffix:
		if r.suffix >= payloadSize {
			return 0, payloadSize - 1, nil
		}

		return payloadSize - r.suffix, payloadSize - 1, nil
	case rangeFrom:
		if r.first >= payloadSize {
			return 0, 0, fmt.Errorf("%w: first byte position %d of %d", ErrRangeNotSatisfiable, r.first, payloadSize)
		}

		return r.first, payloadSize - 1, nil
	default:
		if r.first >= payloadSize {
			return 0, 0, fmt.Errorf("%w: first byte position %d of %d", ErrRangeNotSatisfiable, r.first, payloadSize)
		}

		return r.first, min(r.last, payloadSize-1), nil
	}
}
