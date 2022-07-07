package handlers

import (
	"testing"

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
