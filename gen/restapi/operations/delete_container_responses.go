// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// DeleteContainerOKCode is the HTTP code returned for type DeleteContainerOK
const DeleteContainerOKCode int = 200

/*DeleteContainerOK Successful deletion

swagger:response deleteContainerOK
*/
type DeleteContainerOK struct {

	/*
	  In: Body
	*/
	Payload *models.SuccessResponse `json:"body,omitempty"`
}

// NewDeleteContainerOK creates DeleteContainerOK with default headers values
func NewDeleteContainerOK() *DeleteContainerOK {

	return &DeleteContainerOK{}
}

// WithPayload adds the payload to the delete container o k response
func (o *DeleteContainerOK) WithPayload(payload *models.SuccessResponse) *DeleteContainerOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete container o k response
func (o *DeleteContainerOK) SetPayload(payload *models.SuccessResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteContainerOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteContainerBadRequestCode is the HTTP code returned for type DeleteContainerBadRequest
const DeleteContainerBadRequestCode int = 400

/*DeleteContainerBadRequest Bad request

swagger:response deleteContainerBadRequest
*/
type DeleteContainerBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewDeleteContainerBadRequest creates DeleteContainerBadRequest with default headers values
func NewDeleteContainerBadRequest() *DeleteContainerBadRequest {

	return &DeleteContainerBadRequest{}
}

// WithPayload adds the payload to the delete container bad request response
func (o *DeleteContainerBadRequest) WithPayload(payload *models.ErrorResponse) *DeleteContainerBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete container bad request response
func (o *DeleteContainerBadRequest) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteContainerBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
