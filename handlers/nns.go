package handlers

import (
	"github.com/nspcc-dev/neofs-sdk-go/user"
)

type (
	noopNNSResolver struct {
	}
)

func (r *noopNNSResolver) HasUser(_ string, _ user.ID) (bool, error) {
	return true, nil
}
