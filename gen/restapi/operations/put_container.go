// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"context"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// PutContainerHandlerFunc turns a function with the right signature into a put container handler
type PutContainerHandlerFunc func(PutContainerParams, *models.Principal) middleware.Responder

// Handle executing the request and returning a response
func (fn PutContainerHandlerFunc) Handle(params PutContainerParams, principal *models.Principal) middleware.Responder {
	return fn(params, principal)
}

// PutContainerHandler interface for that can handle valid put container params
type PutContainerHandler interface {
	Handle(PutContainerParams, *models.Principal) middleware.Responder
}

// NewPutContainer creates a new http.Handler for the put container operation
func NewPutContainer(ctx *middleware.Context, handler PutContainerHandler) *PutContainer {
	return &PutContainer{Context: ctx, Handler: handler}
}

/* PutContainer swagger:route PUT /containers putContainer

Create new container in NeoFS

*/
type PutContainer struct {
	Context *middleware.Context
	Handler PutContainerHandler
}

func (o *PutContainer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewPutContainerParams()
	uprinc, aCtx, err := o.Context.Authorize(r, route)
	if err != nil {
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}
	if aCtx != nil {
		*r = *aCtx
	}
	var principal *models.Principal
	if uprinc != nil {
		principal = uprinc.(*models.Principal) // this is really a models.Principal, I promise
	}

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params, principal) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}

// PutContainerBody put container body
// Example: {"basicAcl":"public-read-write","containerId":"container","placementPolicy":"REP 3"}
//
// swagger:model PutContainerBody
type PutContainerBody struct {

	// basic Acl
	BasicACL string `json:"basicAcl,omitempty"`

	// container name
	ContainerName string `json:"containerName,omitempty"`

	// placement policy
	PlacementPolicy string `json:"placementPolicy,omitempty"`
}

// Validate validates this put container body
func (o *PutContainerBody) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this put container body based on context it is used
func (o *PutContainerBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PutContainerBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PutContainerBody) UnmarshalBinary(b []byte) error {
	var res PutContainerBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}

// PutContainerOKBody put container o k body
// Example: {"containerId":"5HZTn5qkRnmgSz9gSrw22CEdPPk6nQhkwf2Mgzyvkikv"}
//
// swagger:model PutContainerOKBody
type PutContainerOKBody struct {

	// container Id
	// Required: true
	ContainerID *string `json:"containerId"`
}

// Validate validates this put container o k body
func (o *PutContainerOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	if err := o.validateContainerID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (o *PutContainerOKBody) validateContainerID(formats strfmt.Registry) error {

	if err := validate.Required("putContainerOK"+"."+"containerId", "body", o.ContainerID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this put container o k body based on context it is used
func (o *PutContainerOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (o *PutContainerOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *PutContainerOKBody) UnmarshalBinary(b []byte) error {
	var res PutContainerOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
