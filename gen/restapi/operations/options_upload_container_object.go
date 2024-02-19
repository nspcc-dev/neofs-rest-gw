// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// OptionsUploadContainerObjectHandlerFunc turns a function with the right signature into a options upload container object handler
type OptionsUploadContainerObjectHandlerFunc func(OptionsUploadContainerObjectParams) middleware.Responder

// Handle executing the request and returning a response
func (fn OptionsUploadContainerObjectHandlerFunc) Handle(params OptionsUploadContainerObjectParams) middleware.Responder {
	return fn(params)
}

// OptionsUploadContainerObjectHandler interface for that can handle valid options upload container object params
type OptionsUploadContainerObjectHandler interface {
	Handle(OptionsUploadContainerObjectParams) middleware.Responder
}

// NewOptionsUploadContainerObject creates a new http.Handler for the options upload container object operation
func NewOptionsUploadContainerObject(ctx *middleware.Context, handler OptionsUploadContainerObjectHandler) *OptionsUploadContainerObject {
	return &OptionsUploadContainerObject{Context: ctx, Handler: handler}
}

/* OptionsUploadContainerObject swagger:route OPTIONS /upload/{containerId} optionsUploadContainerObject

OptionsUploadContainerObject options upload container object API

*/
type OptionsUploadContainerObject struct {
	Context *middleware.Context
	Handler OptionsUploadContainerObjectHandler
}

func (o *OptionsUploadContainerObject) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewOptionsUploadContainerObjectParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}