package handlers_test

import (
	"testing"

	"github.com/nspcc-dev/neofs-rest-gw/handlers"
	"github.com/stretchr/testify/require"
)

func TestNewAPI(t *testing.T) {
	t.Run("non-positive buffer size limit", func(t *testing.T) {
		_, err := handlers.NewAPI(new(handlers.PrmAPI))
		require.EqualError(t, err, "zero payload buffer size limit")
	})
}
