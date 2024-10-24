package handlers

import (
	"context"
	"errors"
	"net/http"

	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
)

func getResponseCodeFromStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}

	switch {
	case errors.Is(err, context.Canceled):
		return http.StatusGatewayTimeout
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(err, apistatus.ErrEACLNotFound):
		return http.StatusNotFound
	case errors.Is(err, apistatus.ErrContainerNotFound):
		return http.StatusNotFound
	case errors.Is(err, apistatus.ErrSessionTokenNotFound):
		return http.StatusNotFound
	case errors.Is(err, apistatus.ErrSessionTokenExpired):
		return http.StatusForbidden
	case errors.Is(err, apistatus.ErrObjectLocked):
		return http.StatusConflict
	case errors.Is(err, apistatus.ErrObjectAlreadyRemoved):
		return http.StatusGone
	case errors.Is(err, apistatus.ErrLockNonRegularObject):
		return http.StatusForbidden
	case errors.Is(err, apistatus.ErrObjectAccessDenied):
		return http.StatusForbidden
	case errors.Is(err, apistatus.ErrObjectNotFound):
		return http.StatusNotFound
	case errors.Is(err, apistatus.ErrObjectOutOfRange):
		return http.StatusRequestedRangeNotSatisfiable
	case errors.Is(err, apistatus.ErrServerInternal):
		return http.StatusBadGateway
	case errors.Is(err, apistatus.ErrWrongMagicNumber):
		return http.StatusBadGateway
	case errors.Is(err, apistatus.ErrSignatureVerification):
		return http.StatusBadGateway
	case errors.Is(err, apistatus.ErrNodeUnderMaintenance):
		return http.StatusBadGateway

	default:
		return http.StatusInternalServerError
	}
}
