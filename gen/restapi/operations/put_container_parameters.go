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

// NewPutContainerParams creates a new PutContainerParams object
// with the default values initialized.
func NewPutContainerParams() PutContainerParams {

	var (
		// initialize parameters with default values

		nameScopeGlobalDefault = bool(false)
		walletConnectDefault   = bool(false)
	)

	return PutContainerParams{
		NameScopeGlobal: &nameScopeGlobalDefault,

		WalletConnect: &walletConnectDefault,
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
	XBearerSignature string
	/*Hex encoded the public part of the key that signed the bearer token
	  Required: true
	  In: header
	*/
	XBearerSignatureKey string
	/*Container info
	  Required: true
	  In: body
	*/
	Container *models.ContainerPutInfo
	/*Provide this parameter to register container name in NNS service
	  In: query
	  Default: false
	*/
	NameScopeGlobal *bool
	/*Use wallect connect signature scheme or not
	  In: query
	  Default: false
	*/
	WalletConnect *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewPutContainerParams() beforehand.
func (o *PutContainerParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	if err := o.bindXBearerSignature(r.Header[http.CanonicalHeaderKey("X-Bearer-Signature")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if err := o.bindXBearerSignatureKey(r.Header[http.CanonicalHeaderKey("X-Bearer-Signature-Key")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if runtime.HasBody(r) {
		defer r.Body.Close()
		var body models.ContainerPutInfo
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
				o.Container = &body
			}
		}
	} else {
		res = append(res, errors.Required("container", "body", ""))
	}

	qNameScopeGlobal, qhkNameScopeGlobal, _ := qs.GetOK("name-scope-global")
	if err := o.bindNameScopeGlobal(qNameScopeGlobal, qhkNameScopeGlobal, route.Formats); err != nil {
		res = append(res, err)
	}

	qWalletConnect, qhkWalletConnect, _ := qs.GetOK("walletConnect")
	if err := o.bindWalletConnect(qWalletConnect, qhkWalletConnect, route.Formats); err != nil {
		res = append(res, err)
	}
	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindXBearerSignature binds and validates parameter XBearerSignature from header.
func (o *PutContainerParams) bindXBearerSignature(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("X-Bearer-Signature", "header", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("X-Bearer-Signature", "header", raw); err != nil {
		return err
	}
	o.XBearerSignature = raw

	return nil
}

// bindXBearerSignatureKey binds and validates parameter XBearerSignatureKey from header.
func (o *PutContainerParams) bindXBearerSignatureKey(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("X-Bearer-Signature-Key", "header", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("X-Bearer-Signature-Key", "header", raw); err != nil {
		return err
	}
	o.XBearerSignatureKey = raw

	return nil
}

// bindNameScopeGlobal binds and validates parameter NameScopeGlobal from query.
func (o *PutContainerParams) bindNameScopeGlobal(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("name-scope-global", "query", "bool", raw)
	}
	o.NameScopeGlobal = &value

	return nil
}

// bindWalletConnect binds and validates parameter WalletConnect from query.
func (o *PutContainerParams) bindWalletConnect(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
		return errors.InvalidType("walletConnect", "query", "bool", raw)
	}
	o.WalletConnect = &value

	return nil
}
