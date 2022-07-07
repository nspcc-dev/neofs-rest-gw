// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// DeleteObjectOKCode is the HTTP code returned for type DeleteObjectOK
const DeleteObjectOKCode int = 200

/*DeleteObjectOK Successful deletion

swagger:response deleteObjectOK
*/
type DeleteObjectOK struct {

	/*
	  In: Body
	*/
	Payload *models.SuccessResponse `json:"body,omitempty"`
}

// NewDeleteObjectOK creates DeleteObjectOK with default headers values
func NewDeleteObjectOK() *DeleteObjectOK {

	return &DeleteObjectOK{}
}

// WithPayload adds the payload to the delete object o k response
func (o *DeleteObjectOK) WithPayload(payload *models.SuccessResponse) *DeleteObjectOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete object o k response
func (o *DeleteObjectOK) SetPayload(payload *models.SuccessResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteObjectOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteObjectBadRequestCode is the HTTP code returned for type DeleteObjectBadRequest
const DeleteObjectBadRequestCode int = 400

/*DeleteObjectBadRequest Bad request

swagger:response deleteObjectBadRequest
*/
type DeleteObjectBadRequest struct {

	/*
	  In: Body
	*/
	Payload models.Error `json:"body,omitempty"`
}

// NewDeleteObjectBadRequest creates DeleteObjectBadRequest with default headers values
func NewDeleteObjectBadRequest() *DeleteObjectBadRequest {

	return &DeleteObjectBadRequest{}
}

// WithPayload adds the payload to the delete object bad request response
func (o *DeleteObjectBadRequest) WithPayload(payload models.Error) *DeleteObjectBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete object bad request response
func (o *DeleteObjectBadRequest) SetPayload(payload models.Error) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteObjectBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
