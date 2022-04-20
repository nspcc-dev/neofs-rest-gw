// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// ObjectInfo object info
// Example: {"attribute":[{"key":"Timestamp","value":"1648810072"},{"key":"Name","value":"object"}],"containerId":"5HZTn5qkRnmgSz9gSrw22CEdPPk6nQhkwf2Mgzyvkikv","objectId":"8N3o7Dtr6T1xteCt6eRwhpmJ7JhME58Hyu1dvaswuTDd","ownerId":"NbUgTSFvPmsRxmGeWpuuGeJUoRoi6PErcM"}
//
// swagger:model ObjectInfo
type ObjectInfo struct {

	// attributes
	// Required: true
	Attributes []*Attribute `json:"attributes"`

	// container Id
	// Required: true
	ContainerID *string `json:"containerId"`

	// object Id
	// Required: true
	ObjectID *string `json:"objectId"`

	// Object full payload size
	// Required: true
	ObjectSize *int64 `json:"objectSize"`

	// owner Id
	// Required: true
	OwnerID *string `json:"ownerId"`

	// Base64 encoded object payload
	Payload string `json:"payload,omitempty"`

	// Payload size in response
	// Required: true
	PayloadSize *int64 `json:"payloadSize"`
}

// Validate validates this object info
func (m *ObjectInfo) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttributes(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContainerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateObjectID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateObjectSize(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOwnerID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePayloadSize(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ObjectInfo) validateAttributes(formats strfmt.Registry) error {

	if err := validate.Required("attributes", "body", m.Attributes); err != nil {
		return err
	}

	for i := 0; i < len(m.Attributes); i++ {
		if swag.IsZero(m.Attributes[i]) { // not required
			continue
		}

		if m.Attributes[i] != nil {
			if err := m.Attributes[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *ObjectInfo) validateContainerID(formats strfmt.Registry) error {

	if err := validate.Required("containerId", "body", m.ContainerID); err != nil {
		return err
	}

	return nil
}

func (m *ObjectInfo) validateObjectID(formats strfmt.Registry) error {

	if err := validate.Required("objectId", "body", m.ObjectID); err != nil {
		return err
	}

	return nil
}

func (m *ObjectInfo) validateObjectSize(formats strfmt.Registry) error {

	if err := validate.Required("objectSize", "body", m.ObjectSize); err != nil {
		return err
	}

	return nil
}

func (m *ObjectInfo) validateOwnerID(formats strfmt.Registry) error {

	if err := validate.Required("ownerId", "body", m.OwnerID); err != nil {
		return err
	}

	return nil
}

func (m *ObjectInfo) validatePayloadSize(formats strfmt.Registry) error {

	if err := validate.Required("payloadSize", "body", m.PayloadSize); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this object info based on the context it is used
func (m *ObjectInfo) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttributes(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ObjectInfo) contextValidateAttributes(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Attributes); i++ {

		if m.Attributes[i] != nil {
			if err := m.Attributes[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("attributes" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("attributes" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *ObjectInfo) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ObjectInfo) UnmarshalBinary(b []byte) error {
	var res ObjectInfo
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
