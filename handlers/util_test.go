package handlers

import (
	"math"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPrepareExpirationHeader(t *testing.T) {
	tomorrow := time.Now().Add(24 * time.Hour)
	tomorrowUnix := tomorrow.Unix()
	tomorrowUnixNano := tomorrow.UnixNano()
	tomorrowUnixMilli := tomorrowUnixNano / 1e6

	epoch := "100"
	duration := "24h"
	timestampSec := strconv.FormatInt(tomorrowUnix, 10)
	timestampMilli := strconv.FormatInt(tomorrowUnixMilli, 10)
	timestampNano := strconv.FormatInt(tomorrowUnixNano, 10)

	defaultDurations := &epochDurations{
		currentEpoch:    10,
		secondsPerEpoch: 101,
	}

	epochPerDay := uint64((24 * time.Hour).Seconds()) / defaultDurations.secondsPerEpoch
	if uint64((24*time.Hour).Seconds())%defaultDurations.secondsPerEpoch != 0 {
		epochPerDay++
	}

	defaultExpEpoch := strconv.FormatUint(defaultDurations.currentEpoch+epochPerDay, 10)

	for _, tc := range []struct {
		name      string
		headers   map[string]string
		durations *epochDurations
		err       bool
		expected  map[string]string
	}{
		{
			name:     "valid epoch",
			headers:  map[string]string{object.AttributeExpirationEpoch: epoch},
			expected: map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name: "valid epoch, valid duration",
			headers: map[string]string{
				object.AttributeExpirationEpoch: epoch,
				ExpirationDurationAttr:          duration,
			},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name: "valid epoch, valid rfc3339",
			headers: map[string]string{
				object.AttributeExpirationEpoch: epoch,
				ExpirationRFC3339Attr:           tomorrow.Format(time.RFC3339),
			},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name: "valid epoch, valid timestamp sec",
			headers: map[string]string{
				object.AttributeExpirationEpoch: epoch,
				ExpirationTimestampAttr:         timestampSec,
			},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name: "valid epoch, valid timestamp milli",
			headers: map[string]string{
				object.AttributeExpirationEpoch: epoch,
				ExpirationTimestampAttr:         timestampMilli,
			},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name: "valid epoch, valid timestamp nano",
			headers: map[string]string{
				object.AttributeExpirationEpoch: epoch,
				ExpirationTimestampAttr:         timestampNano,
			},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: epoch},
		},
		{
			name:      "valid timestamp sec",
			headers:   map[string]string{ExpirationTimestampAttr: timestampSec},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: defaultExpEpoch},
		},
		{
			name:      "valid duration",
			headers:   map[string]string{ExpirationDurationAttr: duration},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: defaultExpEpoch},
		},
		{
			name:      "valid rfc3339",
			headers:   map[string]string{ExpirationRFC3339Attr: tomorrow.Format(time.RFC3339)},
			durations: defaultDurations,
			expected:  map[string]string{object.AttributeExpirationEpoch: defaultExpEpoch},
		},
		{
			name:    "valid max uint 64",
			headers: map[string]string{ExpirationRFC3339Attr: tomorrow.Format(time.RFC3339)},
			durations: &epochDurations{
				currentEpoch:    math.MaxUint64 - 1,
				secondsPerEpoch: defaultDurations.secondsPerEpoch,
			},
			expected: map[string]string{object.AttributeExpirationEpoch: strconv.FormatUint(uint64(math.MaxUint64), 10)},
		},
		{
			name:    "invalid timestamp sec",
			headers: map[string]string{ExpirationTimestampAttr: "abc"},
			err:     true,
		},
		{
			name:    "invalid timestamp sec zero",
			headers: map[string]string{ExpirationTimestampAttr: "0"},
			err:     true,
		},
		{
			name:    "invalid duration",
			headers: map[string]string{ExpirationDurationAttr: "1d"},
			err:     true,
		},
		{
			name:    "invalid duration negative",
			headers: map[string]string{ExpirationDurationAttr: "-5h"},
			err:     true,
		},
		{
			name:    "invalid rfc3339",
			headers: map[string]string{ExpirationRFC3339Attr: "abc"},
			err:     true,
		},
		{
			name:    "invalid rfc3339 zero",
			headers: map[string]string{ExpirationRFC3339Attr: time.RFC3339},
			err:     true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			err := prepareExpirationHeader(tc.headers, tc.durations, now)
			if tc.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, tc.headers)
			}
		})
	}
}

func TestFilter(t *testing.T) {
	log := zap.NewNop()

	t.Run("duplicate keys error", func(t *testing.T) {
		req := http.Header{}
		req.Add("X-Attribute-Dup-Key", "first-value")
		req.Add("X-Attribute-Dup-Key", "second-value")
		_, err := filterHeaders(log, req)
		require.Error(t, err)
	})

	t.Run("duplicate system keys error", func(t *testing.T) {
		req := http.Header{}
		req.Add("X-Attribute-Neofs-Dup-Key", "first-value")
		req.Add("X-Attribute-Neofs-Dup-Key", "second-value")
		_, err := filterHeaders(log, req)
		require.Error(t, err)
	})

	req := http.Header{}

	req.Set("X-Attribute-Neofs-Expiration-Epoch1", "101")
	req.Set("X-Attribute-NEOFS-Expiration-Epoch2", "102")
	req.Set("X-Attribute-neofs-Expiration-Epoch3", "103")
	req.Set("X-Attribute-FileName", "FileName") // This one will be overridden.
	req.Set("X-Attribute-filename", "filename")
	req.Set("X-Attribute-fIlePaTh", "fIlePaTh/") // This one will be overridden.
	req.Set("X-Attribute-Filepath", "Filepath/")
	req.Set("X-Attribute-FilePath1", "FilePath/1")
	req.Set("X-Attribute-My-Attribute", "value")
	req.Set("X-Attribute-MyAttribute", "value2")
	req.Set("X-Attribute-Empty-Value", "") // This one will be skipped.
	req.Set("X-Attribute-", "prefix only") // This one will be skipped.
	req.Set("No-Prefix", "value")          // This one will be skipped.

	expected := map[string]string{
		"__NEOFS__EXPIRATION_EPOCH1": "101",
		"__NEOFS__EXPIRATION_EPOCH2": "102",
		"__NEOFS__EXPIRATION_EPOCH3": "103",
		"FileName":                   "filename",
		"FilePath":                   "Filepath/",
		"Filepath1":                  "FilePath/1",
		"My-Attribute":               "value",
		"Myattribute":                "value2",
	}

	result, err := filterHeaders(log, req)
	require.NoError(t, err)
	require.Equal(t, expected, result)
}

func Test_getOffsetAndLimit(t *testing.T) {
	type args struct {
		offset *int
		limit  *int
	}
	tests := []struct {
		name       string
		args       args
		wantOffset int
		wantLimit  int
		wantErr    bool
	}{
		{name: "default", args: args{}, wantOffset: offsetDefault, wantLimit: limitDefault, wantErr: false},
		{name: "invalid offset", args: args{offset: newInt(offsetMin - 1)}, wantErr: true},
		{name: "valid offset", args: args{offset: newInt(offsetMin)}, wantOffset: offsetMin, wantLimit: limitDefault, wantErr: false},
		{name: "invalid limit, lower", args: args{limit: newInt(limitMin - 1)}, wantErr: true},
		{name: "invalid limit, greater", args: args{limit: newInt(limitMax + 1)}, wantErr: true},
		{name: "valid limit", args: args{limit: newInt(limitMin)}, wantOffset: offsetDefault, wantLimit: limitMin, wantErr: false},
		{name: "valid limit", args: args{limit: newInt(limitMax)}, wantOffset: offsetDefault, wantLimit: limitMax, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getOffsetAndLimit(tt.args.offset, tt.args.limit)
			if (err != nil) != tt.wantErr {
				t.Errorf("getOffsetAndLimit() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantOffset {
				t.Errorf("getOffsetAndLimit() got = %v, wantOffset %v", got, tt.wantOffset)
			}
			if got1 != tt.wantLimit {
				t.Errorf("getOffsetAndLimit() got1 = %v, wantOffset %v", got1, tt.wantLimit)
			}
		})
	}
}

func newInt(v int) *int {
	return &v
}

func stringPtr(s string) *string {
	return &s
}
func Test_paramIsPositive(t *testing.T) {
	type args struct {
		s *string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{name: "empty string", args: args{stringPtr("")}, want: false},
		{name: "false string", args: args{stringPtr("false")}, want: false},
		{name: "random string", args: args{stringPtr("@$FC1*")}, want: false},
		{name: "0 number", args: args{stringPtr("0")}, want: false},
		{name: "2 number", args: args{stringPtr("2")}, want: false},
		{name: "1 number", args: args{stringPtr("1")}, want: true},
		{name: "true string", args: args{stringPtr("true")}, want: true},
		{name: "YES string", args: args{stringPtr("YES")}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := paramIsPositive(tt.args.s); got != tt.want {
				t.Errorf("paramIsPositive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseAndFilterAttributes(t *testing.T) {
	type args struct {
		logger   *zap.Logger
		jsonAttr *string
	}

	l := zap.NewExample()

	var nilStr *string
	errStr1, errStr2, errStr3 := "", "{", "JSON"
	emptyStr1, emptyStr2, emptyStr3, emptyStr4 := `{}`, `{"":""}`, `{"key":""}`, `{"":"val"}`
	str1 := `{
		"skip empty":"",
		"":"skip empty",
		"__NEOFS__EXPIRATION_EPOCH":"1000",
		"file-N%me":"simple %bj filename",
		"writer":"Leo Tolstoy",
		"Chapter1":"pe@ce",
		"chapter2":"war"}`

	emptyMap := make(map[string]string)
	map1 := map[string]string{
		"__NEOFS__EXPIRATION_EPOCH": "1000",
		"file-N%me":                 "simple %bj filename",
		"writer":                    "Leo Tolstoy",
		"Chapter1":                  "pe@ce",
		"chapter2":                  "war",
	}

	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{name: "nil str pointer", args: args{l, nilStr}, want: emptyMap, wantErr: false},

		{name: "wrong string 1", args: args{l, &errStr1}, want: nil, wantErr: true},
		{name: "wrong string 2", args: args{l, &errStr2}, want: nil, wantErr: true},
		{name: "wrong string 3", args: args{l, &errStr3}, want: nil, wantErr: true},

		{name: "empty result map 1", args: args{l, &emptyStr1}, want: emptyMap, wantErr: false},
		{name: "empty result map 2", args: args{l, &emptyStr2}, want: emptyMap, wantErr: false},
		{name: "empty result map 3", args: args{l, &emptyStr3}, want: emptyMap, wantErr: false},
		{name: "empty result map 4", args: args{l, &emptyStr4}, want: emptyMap, wantErr: false},

		{name: "correct", args: args{l, &str1}, want: map1, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAndFilterAttributes(tt.args.logger, tt.args.jsonAttr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAndFilterAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAndFilterAttributes() got = %v, want %v", got, tt.want)
			}
		})
	}
}
