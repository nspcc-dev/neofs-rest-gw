// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"io"
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"

	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
)

// NewAuthParams creates a new AuthParams object
// with the default values initialized.
func NewAuthParams() AuthParams {

	var (
		// initialize parameters with default values

		xNeofsTokenLifetimeDefault = int64(100)
	)

	return AuthParams{
		XNeofsTokenLifetime: &xNeofsTokenLifetimeDefault,
	}
}

// AuthParams contains all the bound params for the auth operation
// typically these are obtained from a http.Request
//
// swagger:parameters auth
type AuthParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Token lifetime in epoch
	  In: header
	  Default: 100
	*/
	XNeofsTokenLifetime *int64
	/*Supported operation scope for token
	  Required: true
	  In: header
	*/
	XNeofsTokenScope string
	/*Public key of user
	  Required: true
	  In: header
	*/
	XNeofsTokenSignatureKey string
	/*Bearer token
	  Required: true
	  In: body
	*/
	Token *models.Bearer
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewAuthParams() beforehand.
func (o *AuthParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if err := o.bindXNeofsTokenLifetime(r.Header[http.CanonicalHeaderKey("X-Neofs-Token-Lifetime")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if err := o.bindXNeofsTokenScope(r.Header[http.CanonicalHeaderKey("X-Neofs-Token-Scope")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if err := o.bindXNeofsTokenSignatureKey(r.Header[http.CanonicalHeaderKey("X-Neofs-Token-Signature-Key")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.Bearer
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("token", "body", ""))
			} else {
				res = append(res, errors.NewParseError("token", "body", "", err))
			}
		} else {
			// validate body object
			if err := body.Validate(route.Formats); err != nil {
				res = append(res, err)
			}

			ctx := validate.WithOperationRequest(context.Background())
			if err := body.ContextValidate(ctx, route.Formats); err != nil {
				res = append(res, err)
			}

			if len(res) == 0 {
				o.Token = &body
			}
		}
	} else {
		res = append(res, errors.Required("token", "body", ""))
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindXNeofsTokenLifetime binds and validates parameter XNeofsTokenLifetime from header.
func (o *AuthParams) bindXNeofsTokenLifetime(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewAuthParams()
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("X-Neofs-Token-Lifetime", "header", "int64", raw)
	}
	o.XNeofsTokenLifetime = &value

	return nil
}

// bindXNeofsTokenScope binds and validates parameter XNeofsTokenScope from header.
func (o *AuthParams) bindXNeofsTokenScope(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("X-Neofs-Token-Scope", "header", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("X-Neofs-Token-Scope", "header", raw); err != nil {
		return err
	}
	o.XNeofsTokenScope = raw

	if err := o.validateXNeofsTokenScope(formats); err != nil {
		return err
	}

	return nil
}

// validateXNeofsTokenScope carries on validations for parameter XNeofsTokenScope
func (o *AuthParams) validateXNeofsTokenScope(formats strfmt.Registry) error {

	if err := validate.EnumCase("X-Neofs-Token-Scope", "header", o.XNeofsTokenScope, []interface{}{"object", "container"}, true); err != nil {
		return err
	}

	return nil
}

// bindXNeofsTokenSignatureKey binds and validates parameter XNeofsTokenSignatureKey from header.
func (o *AuthParams) bindXNeofsTokenSignatureKey(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("X-Neofs-Token-Signature-Key", "header", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("X-Neofs-Token-Signature-Key", "header", raw); err != nil {
		return err
	}
	o.XNeofsTokenSignatureKey = raw

	return nil
}
