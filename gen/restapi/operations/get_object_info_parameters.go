// Code generated by go-swagger; DO NOT EDIT.

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// NewGetObjectInfoParams creates a new GetObjectInfoParams object
// with the default values initialized.
func NewGetObjectInfoParams() GetObjectInfoParams {

	var (
		// initialize parameters with default values

		maxPayloadSizeDefault = int64(4.194304e+06)

		walletConnectDefault = bool(false)
	)

	return GetObjectInfoParams{
		MaxPayloadSize: &maxPayloadSizeDefault,

		WalletConnect: &walletConnectDefault,
	}
}

// GetObjectInfoParams contains all the bound params for the get object info operation
// typically these are obtained from a http.Request
//
// swagger:parameters getObjectInfo
type GetObjectInfoParams struct {

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
	/*Base58 encoded container id
	  Required: true
	  In: path
	*/
	ContainerID string
	/*Max payload size (in bytes) that can be included in the response.
	If the actual size is greater than this params the payload won't be included in the response.

	  Maximum: 5.24288e+08
	  Minimum: 0
	  In: query
	  Default: 4.194304e+06
	*/
	MaxPayloadSize *int64
	/*Base58 encoded object id
	  Required: true
	  In: path
	*/
	ObjectID string
	/*
	  Minimum: 1
	  In: query
	*/
	RangeLength *int64
	/*
	  Minimum: 0
	  In: query
	*/
	RangeOffset *int64
	/*Use wallect connect signature scheme or not
	  In: query
	  Default: false
	*/
	WalletConnect *bool
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewGetObjectInfoParams() beforehand.
func (o *GetObjectInfoParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	if err := o.bindXBearerSignature(r.Header[http.CanonicalHeaderKey("X-Bearer-Signature")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	if err := o.bindXBearerSignatureKey(r.Header[http.CanonicalHeaderKey("X-Bearer-Signature-Key")], true, route.Formats); err != nil {
		res = append(res, err)
	}

	rContainerID, rhkContainerID, _ := route.Params.GetOK("containerId")
	if err := o.bindContainerID(rContainerID, rhkContainerID, route.Formats); err != nil {
		res = append(res, err)
	}

	qMaxPayloadSize, qhkMaxPayloadSize, _ := qs.GetOK("max-payload-size")
	if err := o.bindMaxPayloadSize(qMaxPayloadSize, qhkMaxPayloadSize, route.Formats); err != nil {
		res = append(res, err)
	}

	rObjectID, rhkObjectID, _ := route.Params.GetOK("objectId")
	if err := o.bindObjectID(rObjectID, rhkObjectID, route.Formats); err != nil {
		res = append(res, err)
	}

	qRangeLength, qhkRangeLength, _ := qs.GetOK("range-length")
	if err := o.bindRangeLength(qRangeLength, qhkRangeLength, route.Formats); err != nil {
		res = append(res, err)
	}

	qRangeOffset, qhkRangeOffset, _ := qs.GetOK("range-offset")
	if err := o.bindRangeOffset(qRangeOffset, qhkRangeOffset, route.Formats); err != nil {
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
func (o *GetObjectInfoParams) bindXBearerSignature(rawData []string, hasKey bool, formats strfmt.Registry) error {
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
func (o *GetObjectInfoParams) bindXBearerSignatureKey(rawData []string, hasKey bool, formats strfmt.Registry) error {
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

// bindContainerID binds and validates parameter ContainerID from path.
func (o *GetObjectInfoParams) bindContainerID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.ContainerID = raw

	return nil
}

// bindMaxPayloadSize binds and validates parameter MaxPayloadSize from query.
func (o *GetObjectInfoParams) bindMaxPayloadSize(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewGetObjectInfoParams()
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("max-payload-size", "query", "int64", raw)
	}
	o.MaxPayloadSize = &value

	if err := o.validateMaxPayloadSize(formats); err != nil {
		return err
	}

	return nil
}

// validateMaxPayloadSize carries on validations for parameter MaxPayloadSize
func (o *GetObjectInfoParams) validateMaxPayloadSize(formats strfmt.Registry) error {

	if err := validate.MinimumInt("max-payload-size", "query", *o.MaxPayloadSize, 0, false); err != nil {
		return err
	}

	if err := validate.MaximumInt("max-payload-size", "query", *o.MaxPayloadSize, 5.24288e+08, false); err != nil {
		return err
	}

	return nil
}

// bindObjectID binds and validates parameter ObjectID from path.
func (o *GetObjectInfoParams) bindObjectID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// Parameter is provided by construction from the route
	o.ObjectID = raw

	return nil
}

// bindRangeLength binds and validates parameter RangeLength from query.
func (o *GetObjectInfoParams) bindRangeLength(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("range-length", "query", "int64", raw)
	}
	o.RangeLength = &value

	if err := o.validateRangeLength(formats); err != nil {
		return err
	}

	return nil
}

// validateRangeLength carries on validations for parameter RangeLength
func (o *GetObjectInfoParams) validateRangeLength(formats strfmt.Registry) error {

	if err := validate.MinimumInt("range-length", "query", *o.RangeLength, 1, false); err != nil {
		return err
	}

	return nil
}

// bindRangeOffset binds and validates parameter RangeOffset from query.
func (o *GetObjectInfoParams) bindRangeOffset(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		return nil
	}

	value, err := swag.ConvertInt64(raw)
	if err != nil {
		return errors.InvalidType("range-offset", "query", "int64", raw)
	}
	o.RangeOffset = &value

	if err := o.validateRangeOffset(formats); err != nil {
		return err
	}

	return nil
}

// validateRangeOffset carries on validations for parameter RangeOffset
func (o *GetObjectInfoParams) validateRangeOffset(formats strfmt.Registry) error {

	if err := validate.MinimumInt("range-offset", "query", *o.RangeOffset, 0, false); err != nil {
		return err
	}

	return nil
}

// bindWalletConnect binds and validates parameter WalletConnect from query.
func (o *GetObjectInfoParams) bindWalletConnect(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false

	if raw == "" { // empty values pass all other validations
		// Default values have been previously initialized by NewGetObjectInfoParams()
		return nil
	}

	value, err := swag.ConvertBool(raw)
	if err != nil {
		return errors.InvalidType("walletConnect", "query", "bool", raw)
	}
	o.WalletConnect = &value

	return nil
}
