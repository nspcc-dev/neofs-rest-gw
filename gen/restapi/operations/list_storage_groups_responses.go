// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// ListStorageGroupsOKCode is the HTTP code returned for type ListStorageGroupsOK
const ListStorageGroupsOKCode int = 200

/*ListStorageGroupsOK List of storage groups.

swagger:response listStorageGroupsOK
*/
type ListStorageGroupsOK struct {

	/*
	  In: Body
	*/
	Payload *models.StorageGroupList `json:"body,omitempty"`
}

// NewListStorageGroupsOK creates ListStorageGroupsOK with default headers values
func NewListStorageGroupsOK() *ListStorageGroupsOK {

	return &ListStorageGroupsOK{}
}

// WithPayload adds the payload to the list storage groups o k response
func (o *ListStorageGroupsOK) WithPayload(payload *models.StorageGroupList) *ListStorageGroupsOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list storage groups o k response
func (o *ListStorageGroupsOK) SetPayload(payload *models.StorageGroupList) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListStorageGroupsOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListStorageGroupsBadRequestCode is the HTTP code returned for type ListStorageGroupsBadRequest
const ListStorageGroupsBadRequestCode int = 400

/*ListStorageGroupsBadRequest Bad request.

swagger:response listStorageGroupsBadRequest
*/
type ListStorageGroupsBadRequest struct {

	/*
	  In: Body
	*/
	Payload *models.ErrorResponse `json:"body,omitempty"`
}

// NewListStorageGroupsBadRequest creates ListStorageGroupsBadRequest with default headers values
func NewListStorageGroupsBadRequest() *ListStorageGroupsBadRequest {

	return &ListStorageGroupsBadRequest{}
}

// WithPayload adds the payload to the list storage groups bad request response
func (o *ListStorageGroupsBadRequest) WithPayload(payload *models.ErrorResponse) *ListStorageGroupsBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list storage groups bad request response
func (o *ListStorageGroupsBadRequest) SetPayload(payload *models.ErrorResponse) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListStorageGroupsBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
