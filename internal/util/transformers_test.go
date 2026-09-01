package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/stretchr/testify/require"
)

func TestErrors(t *testing.T) {
	apiErr := fmt.Errorf("some context: %w", apistatus.ContainerNotFound{})

	resp := NewErrorResponse(apiErr)
	data, err := json.Marshal(resp)
	require.NoError(t, err)
	require.Equal(t, `{"code":3072,"message":"some context: status: code = 3072 message = container not found","type":"API"}`, string(data))

	gwErr := fmt.Errorf("some context: %w", errors.New("sanity check error"))

	resp = NewErrorResponse(gwErr)
	data, err = json.Marshal(resp)
	require.NoError(t, err)
	require.Equal(t, `{"message":"some context: sanity check error","type":"GW"}`, string(data))
}

func TestFromNativeOperation(t *testing.T) {
	for _, tc := range []struct {
		op       eacl.Operation
		expected apiserver.Operation
	}{
		{op: eacl.OperationGet, expected: apiserver.GET},
		{op: eacl.OperationHead, expected: apiserver.HEAD},
		{op: eacl.OperationPut, expected: apiserver.PUT},
		{op: eacl.OperationDelete, expected: apiserver.DELETE},
		{op: eacl.OperationSearch, expected: apiserver.SEARCH},
		{op: eacl.OperationRange, expected: apiserver.RANGE},
	} {
		t.Run(tc.op.String(), func(t *testing.T) {
			op, err := FromNativeOperation(tc.op)
			require.NoError(t, err)
			require.Equal(t, tc.expected, op)
		})
	}

	t.Run("range hash is ignored", func(t *testing.T) {
		_, err := FromNativeOperation(eacl.OperationRangeHash)
		require.ErrorIs(t, err, ErrIgnoreEACLOperation)
	})

	t.Run("unsupported", func(t *testing.T) {
		for _, op := range []eacl.Operation{eacl.OperationUnspecified, eacl.Operation(100)} {
			_, err := FromNativeOperation(op)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrIgnoreEACLOperation)
			require.Contains(t, err.Error(), "unsupported operation type")
		}
	})
}

func TestFromNativeRecord(t *testing.T) {
	var (
		targets    = []eacl.Target{eacl.NewTargetByRole(eacl.RoleOthers)}
		othersRole = apiserver.OTHERS
	)

	t.Run("supported operation", func(t *testing.T) {
		var rec = eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationRange, targets)

		record, err := FromNativeRecord(rec)
		require.NoError(t, err)
		require.Equal(t, apiserver.Record{
			Action:    apiserver.DENY,
			Operation: apiserver.RANGE,
			Filters:   []apiserver.Filter{},
			Targets:   []apiserver.Target{{Keys: []string{}, Role: &othersRole}},
		}, record)
	})

	t.Run("range hash is ignored", func(t *testing.T) {
		var rec = eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationRangeHash, targets)

		_, err := FromNativeRecord(rec)
		require.ErrorIs(t, err, ErrIgnoreEACLOperation)
	})

	t.Run("unsupported operation", func(t *testing.T) {
		var rec = eacl.ConstructRecord(eacl.ActionDeny, eacl.OperationUnspecified, targets)

		_, err := FromNativeRecord(rec)
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrIgnoreEACLOperation)
	})
}
