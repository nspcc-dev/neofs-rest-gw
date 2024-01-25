package handlers

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	"github.com/nspcc-dev/neofs-rest-gw/gen/restapi/operations"
)

// ErrorResponseCreator creates an instance of ErrorResponder.
type ErrorResponseCreator func() ErrorResponder

// ErrorResponder is an interface that combines middleware.Responder with the ability to set a payload.
type ErrorResponder interface {
	middleware.Responder
	WithPayload(payload *models.ErrorResponse) ErrorResponder
}

// Wrappers to handle `GetContainerObject` and `GetByAttribute` together.

type GetContainerObjectBadRequestWrapper struct {
	*operations.GetContainerObjectBadRequest
}

func (w GetContainerObjectBadRequestWrapper) WithPayload(payload *models.ErrorResponse) ErrorResponder {
	w.GetContainerObjectBadRequest.WithPayload(payload)
	return w
}

type GetByAttributeBadRequestWrapper struct {
	*operations.GetByAttributeBadRequest
}

func (w GetByAttributeBadRequestWrapper) WithPayload(payload *models.ErrorResponse) ErrorResponder {
	w.GetByAttributeBadRequest.WithPayload(payload)
	return w
}

func NewGetContainerObjectBadRequestWrapper() ErrorResponder {
	return GetContainerObjectBadRequestWrapper{operations.NewGetContainerObjectBadRequest()}
}

func NewGetByAttributeBadRequestWrapper() ErrorResponder {
	return GetByAttributeBadRequestWrapper{operations.NewGetByAttributeBadRequest()}
}

// Wrappers to handle `HeadContainerObject` and `HeadByAttribute` together.

type HeadContainerObjectBadRequestWrapper struct {
	*operations.HeadContainerObjectBadRequest
}

func (w HeadContainerObjectBadRequestWrapper) WithPayload(payload *models.ErrorResponse) ErrorResponder {
	w.HeadContainerObjectBadRequest.WithPayload(payload)
	return w
}

type HeadByAttributeBadRequestWrapper struct {
	*operations.HeadByAttributeBadRequest
}

func (w HeadByAttributeBadRequestWrapper) WithPayload(payload *models.ErrorResponse) ErrorResponder {
	w.HeadByAttributeBadRequest.WithPayload(payload)
	return w
}

func NewHeadContainerObjectBadRequestWrapper() ErrorResponder {
	return HeadContainerObjectBadRequestWrapper{operations.NewHeadContainerObjectBadRequest()}
}

func NewHeadByAttributeBadRequestWrapper() ErrorResponder {
	return HeadByAttributeBadRequestWrapper{operations.NewHeadByAttributeBadRequest()}
}
