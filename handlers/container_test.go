package handlers

import (
	"testing"

	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-sdk-go/container/acl"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	sessionv2 "github.com/nspcc-dev/neofs-sdk-go/session/v2"
	"github.com/stretchr/testify/require"
)

func TestCheckContainerName(t *testing.T) {
	name64 := "container-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	name256 := "container-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{name: "container", valid: true},
		{name: "container-name", valid: true},
		{name: "container.name", valid: true},
		{name: "container2", valid: true},
		{name: "2container.name", valid: true},
		{name: "containerName", valid: false},
		{name: "-container", valid: false},
		{name: "container-", valid: false},
		{name: "container name", valid: false},
		{name: "c", valid: false},
		{name: name64 + ".name", valid: false},
		{name: name256, valid: false},
	} {
		err := checkNNSContainerName(tc.name)
		if tc.valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
}

func tokenForVerb(t *testing.T, cnrID cid.ID, verb sessionv2.Verb) *sessionv2.Token {
	sessionCtx, err := sessionv2.NewContext(cnrID, []sessionv2.Verb{verb})
	require.NoError(t, err)

	var token sessionv2.Token
	require.NoError(t, token.SetContexts([]sessionv2.Context{sessionCtx}))

	return &token
}

func TestInitialEACLTable(t *testing.T) {
	othersRole := apiserver.OTHERS
	records := []apiserver.Record{{
		Operation: apiserver.DELETE,
		Action:    apiserver.DENY,
		Filters:   []apiserver.Filter{},
		Targets:   []apiserver.Target{{Role: &othersRole}},
	}}
	badRecords := []apiserver.Record{{
		Operation: apiserver.GET,
		Action:    apiserver.ALLOW,
		Filters: []apiserver.Filter{{
			HeaderType: apiserver.OBJECT,
			MatchType:  apiserver.NUMGT,
			Key:        "attr",
			Value:      "not-a-number",
		}},
		Targets: []apiserver.Target{{Role: &othersRole}},
	}}

	anyContainerToken := tokenForVerb(t, cid.ID{}, sessionv2.VerbContainerSetEACL)

	var someCnrID cid.ID
	require.NoError(t, someCnrID.DecodeString("5HZTn5qkRnmgSz9gSrw22CEdPPk6nQhkwf2Mgzyvkikv"))

	t.Run("no records", func(t *testing.T) {
		for _, records := range [][]apiserver.Record{nil, {}} {
			table, err := initialEACLTable(records, acl.PublicRWExtended, anyContainerToken)
			require.NoError(t, err)
			require.Nil(t, table)
		}
	})

	t.Run("non-extendable basic ACL", func(t *testing.T) {
		for _, basicACL := range []acl.Basic{acl.Private, acl.PublicRW, acl.PublicRO} {
			_, err := initialEACLTable(records, basicACL, anyContainerToken)
			require.ErrorIs(t, err, errEACLDisabled)
		}
	})

	t.Run("no session token", func(t *testing.T) {
		_, err := initialEACLTable(records, acl.PublicRWExtended, nil)
		require.ErrorIs(t, err, errInvalidEACL)
	})

	t.Run("session token without the verb", func(t *testing.T) {
		token := tokenForVerb(t, cid.ID{}, sessionv2.VerbContainerPut)
		_, err := initialEACLTable(records, acl.PublicRWExtended, token)
		require.ErrorIs(t, err, errInvalidEACL)
	})

	t.Run("session token bound to a container", func(t *testing.T) {
		token := tokenForVerb(t, someCnrID, sessionv2.VerbContainerSetEACL)
		_, err := initialEACLTable(records, acl.PublicRWExtended, token)
		require.ErrorIs(t, err, errInvalidEACL)
	})

	t.Run("invalid record", func(t *testing.T) {
		_, err := initialEACLTable(badRecords, acl.PublicRWExtended, anyContainerToken)
		require.ErrorIs(t, err, errInvalidEACL)
	})

	t.Run("valid", func(t *testing.T) {
		table, err := initialEACLTable(records, acl.PublicRWExtended, anyContainerToken)
		require.NoError(t, err)
		require.NotNil(t, table)
		require.Len(t, table.Records(), 1)
		require.True(t, table.GetCID().IsZero())
	})
}
