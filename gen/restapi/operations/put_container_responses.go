// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// PutContainerOKCode is the HTTP code returned for type PutContainerOK
const PutContainerOKCode int = 200

/*PutContainerOK Identifier of the created container.

swagger:response putContainerOK
*/
type PutContainerOK struct {

	/*
	  In: Body
	*/
	Payload *PutContainerOKBody `json:"body,omitempty"`
}

// NewPutContainerOK creates PutContainerOK with default headers values
func NewPutContainerOK() *PutContainerOK {

	return &PutContainerOK{}
}

// WithPayload adds the payload to the put container o k response
func (o *PutContainerOK) WithPayload(payload *PutContainerOKBody) *PutContainerOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put container o k response
func (o *PutContainerOK) SetPayload(payload *PutContainerOKBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutContainerOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// PutContainerBadRequestCode is the HTTP code returned for type PutContainerBadRequest
const PutContainerBadRequestCode int = 400

/*PutContainerBadRequest Bad request.

swagger:response putContainerBadRequest
*/
type PutContainerBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewPutContainerBadRequest creates PutContainerBadRequest with default headers values
func NewPutContainerBadRequest() *PutContainerBadRequest {

	return &PutContainerBadRequest{}
}

// WithPayload adds the payload to the put container bad request response
func (o *PutContainerBadRequest) WithPayload(payload *models.ErrorResponse) *PutContainerBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the put container bad request response
func (o *PutContainerBadRequest) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *PutContainerBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
