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
)

// NewPutContainerParams creates a new PutContainerParams object
// with the default values initialized.
func NewPutContainerParams() PutContainerParams {

	var (
		// initialize parameters with default values

		skipNativeNameDefault = bool(false)
	)

	return PutContainerParams{
		SkipNativeName: &skipNativeNameDefault,
	}
}

// PutContainerParams contains all the bound params for the put container operation
// typically these are obtained from a http.Request
//
// swagger:parameters putContainer
type PutContainerParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*Base64 encoded signature for bearer token
	  Required: true
	  In: header
	*/
	XNeofsTokenSignature string
	/*Hex encoded the public part of the key that signed the bearer token
	  Required: true
	  In: header
	*/
	XNeofsTokenSignatureKey string
	/*Container info
	  Required: true
	  In: body
	*/
	Container PutContainerBody
	/*Provide this parameter to skip registration container name in NNS service
	  In: query
	  Default: false
	*/
	SkipNativeName *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPutContainerParams() beforehand.
func (o *PutContainerParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	if err := o.bindXNeofsTokenSignature(r.Header[http.CanonicalHeaderKey("X-Neofs-Token-Signature")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if err := o.bindXNeofsTokenSignatureKey(r.Header[http.CanonicalHeaderKey("X-Neofs-Token-Signature-Key")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body PutContainerBody
		if err := route.Consumer.Consume(r.Body, &body); err != nil {
			if err == io.EOF {
				res = append(res, errors.Required("container", "body", ""))
			} else {
				res = append(res, errors.NewParseError("container", "body", "", err))
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
				o.Container = body
			}
		}
	} else {
		res = append(res, errors.Required("container", "body", ""))
	}

	qSkipNativeName, qhkSkipNativeName, _ := qs.GetOK("skip-native-name")
	if err := o.bindSkipNativeName(qSkipNativeName, qhkSkipNativeName, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindXNeofsTokenSignature binds and validates parameter XNeofsTokenSignature from header.
func (o *PutContainerParams) bindXNeofsTokenSignature(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("X-Neofs-Token-Signature", "header", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("X-Neofs-Token-Signature", "header", raw); err != nil {
		return err
	}
	o.XNeofsTokenSignature = raw

	return nil
}

// bindXNeofsTokenSignatureKey binds and validates parameter XNeofsTokenSignatureKey from header.
func (o *PutContainerParams) bindXNeofsTokenSignatureKey(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindSkipNativeName binds and validates parameter SkipNativeName from query.
func (o *PutContainerParams) bindSkipNativeName(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewPutContainerParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("skip-native-name", "query", "bool", raw)
	}
	o.SkipNativeName = &value

	return nil
}
