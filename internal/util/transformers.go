package util

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nspcc-dev/neofs-rest-gw/handlers/apiserver"
	"github.com/nspcc-dev/neofs-sdk-go/bearer"
	apistatus "github.com/nspcc-dev/neofs-sdk-go/client/status"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/object"
	"github.com/nspcc-dev/neofs-sdk-go/session"
)

// ToNativeAction converts [apiserver.Action] to appropriate [eacl.Action].
func ToNativeAction(a apiserver.Action) (eacl.Action, error) {
	switch a {
	case apiserver.ALLOW:
		return eacl.ActionAllow, nil
	case apiserver.DENY:
		return eacl.ActionDeny, nil
	default:
		return eacl.ActionUnknown, fmt.Errorf("unsupported action type: '%s'", a)
	}
}

// FromNativeAction converts [eacl.Action] to appropriate [apiserver.Action].
func FromNativeAction(a eacl.Action) (apiserver.Action, error) {
	switch a {
	case eacl.ActionAllow:
		return apiserver.ALLOW, nil
	case eacl.ActionDeny:
		return apiserver.DENY, nil
	default:
		return "", fmt.Errorf("unsupported action type: '%s'", a)
	}
}

// ToNativeOperation converts [apiserver.Operation] to appropriate [eacl.Operation].
func ToNativeOperation(o apiserver.Operation) (eacl.Operation, error) {
	switch o {
	case apiserver.OperationGET:
		return eacl.OperationGet, nil
	case apiserver.OperationHEAD:
		return eacl.OperationHead, nil
	case apiserver.OperationPUT:
		return eacl.OperationPut, nil
	case apiserver.OperationDELETE:
		return eacl.OperationDelete, nil
	case apiserver.OperationSEARCH:
		return eacl.OperationSearch, nil
	case apiserver.OperationRANGE:
		return eacl.OperationRange, nil
	case apiserver.OperationRANGEHASH:
		return eacl.OperationRangeHash, nil
	default:
		return eacl.OperationUnknown, fmt.Errorf("unsupported operation type: '%s'", o)
	}
}

// FromNativeOperation converts [eacl.Operation] to appropriate [apiserver.Operation].
func FromNativeOperation(o eacl.Operation) (apiserver.Operation, error) {
	switch o {
	case eacl.OperationGet:
		return apiserver.OperationGET, nil
	case eacl.OperationHead:
		return apiserver.OperationHEAD, nil
	case eacl.OperationPut:
		return apiserver.OperationPUT, nil
	case eacl.OperationDelete:
		return apiserver.OperationDELETE, nil
	case eacl.OperationSearch:
		return apiserver.OperationSEARCH, nil
	case eacl.OperationRange:
		return apiserver.OperationRANGE, nil
	case eacl.OperationRangeHash:
		return apiserver.OperationRANGEHASH, nil
	default:
		return "", fmt.Errorf("unsupported operation type: '%s'", o)
	}
}

// ToNativeHeaderType converts [apiserver.HeaderType] to appropriate [eacl.FilterHeaderType].
func ToNativeHeaderType(h apiserver.HeaderType) (eacl.FilterHeaderType, error) {
	switch h {
	case apiserver.OBJECT:
		return eacl.HeaderFromObject, nil
	case apiserver.REQUEST:
		return eacl.HeaderFromRequest, nil
	case apiserver.SERVICE:
		return eacl.HeaderFromService, nil
	default:
		return eacl.HeaderTypeUnknown, fmt.Errorf("unsupported header type: '%s'", h)
	}
}

// FromNativeHeaderType converts [eacl.FilterHeaderType] to appropriate [apiserver.HeaderType].
func FromNativeHeaderType(h eacl.FilterHeaderType) (apiserver.HeaderType, error) {
	switch h {
	case eacl.HeaderFromObject:
		return apiserver.OBJECT, nil
	case eacl.HeaderFromRequest:
		return apiserver.REQUEST, nil
	case eacl.HeaderFromService:
		return apiserver.SERVICE, nil
	default:
		return "", fmt.Errorf("unsupported header type: '%s'", h)
	}
}

// ToNativeMatchType converts [apiserver.MatchType] to appropriate [eacl.Match].
func ToNativeMatchType(t apiserver.MatchType) (eacl.Match, error) {
	switch t {
	case apiserver.STRINGEQUAL:
		return eacl.MatchStringEqual, nil
	case apiserver.STRINGNOTEQUAL:
		return eacl.MatchStringNotEqual, nil
	default:
		return eacl.MatchUnknown, fmt.Errorf("unsupported match type: '%s'", t)
	}
}

// FromNativeMatchType converts [eacl.Match] to appropriate [apiserver.MatchType].
func FromNativeMatchType(t eacl.Match) (apiserver.MatchType, error) {
	switch t {
	case eacl.MatchStringEqual:
		return apiserver.STRINGEQUAL, nil
	case eacl.MatchStringNotEqual:
		return apiserver.STRINGNOTEQUAL, nil
	default:
		return "", fmt.Errorf("unsupported match type: '%s'", t)
	}
}

// ToNativeRole converts [apiserver.Role] to appropriate [eacl.Role].
func ToNativeRole(r apiserver.Role) (eacl.Role, error) {
	switch r {
	case apiserver.USER:
		return eacl.RoleUser, nil
	case apiserver.SYSTEM:
		return eacl.RoleSystem, nil
	case apiserver.OTHERS:
		return eacl.RoleOthers, nil
	case apiserver.KEYS:
		return eacl.RoleUnknown, nil
	default:
		return 0, fmt.Errorf("unsupported role type: '%s'", r)
	}
}

// FromNativeRole converts [eacl.Role] to appropriate [apiserver.Role].
func FromNativeRole(r eacl.Role) (apiserver.Role, error) {
	switch r {
	case eacl.RoleUser:
		return apiserver.USER, nil
	case eacl.RoleSystem:
		return apiserver.SYSTEM, nil
	case eacl.RoleOthers:
		return apiserver.OTHERS, nil
	case eacl.RoleUnknown:
		return apiserver.KEYS, nil
	default:
		return "", fmt.Errorf("unsupported role type: '%s'", r)
	}
}

// ToNativeVerb converts [apiserver.Verb] to appropriate [session.ContainerVerb].
func ToNativeVerb(r apiserver.Verb) (session.ContainerVerb, error) {
	switch r {
	case apiserver.VerbPUT:
		return session.VerbContainerPut, nil
	case apiserver.VerbDELETE:
		return session.VerbContainerDelete, nil
	case apiserver.VerbSETEACL:
		return session.VerbContainerSetEACL, nil
	default:
		return 0, fmt.Errorf("unsupported verb type: '%s'", r)
	}
}

// ToNativeContainerToken converts [apiserver.Rule] to appropriate [session.Container].
func ToNativeContainerToken(tokenRule apiserver.Rule) (session.Container, error) {
	var tok session.Container

	if tokenRule.ContainerId != nil && *tokenRule.ContainerId != "" {
		var cnrID cid.ID
		if err := cnrID.DecodeString(*tokenRule.ContainerId); err != nil {
			return session.Container{}, fmt.Errorf("couldn't parse container id: %w", err)
		}
		tok.ApplyOnlyTo(cnrID)
	}

	verb, err := ToNativeVerb(tokenRule.Verb)
	if err != nil {
		return session.Container{}, err
	}
	tok.ForVerb(verb)

	return tok, nil
}

// ToNativeRecord converts [apiserver.Record] to appropriate [eacl.Record].
func ToNativeRecord(r apiserver.Record) (*eacl.Record, error) {
	var record eacl.Record

	action, err := ToNativeAction(r.Action)
	if err != nil {
		return nil, err
	}
	record.SetAction(action)

	operation, err := ToNativeOperation(r.Operation)
	if err != nil {
		return nil, err
	}
	record.SetOperation(operation)

	for _, filter := range r.Filters {
		headerType, err := ToNativeHeaderType(filter.HeaderType)
		if err != nil {
			return nil, err
		}
		matchType, err := ToNativeMatchType(filter.MatchType)
		if err != nil {
			return nil, err
		}
		if filter.Key == "" || filter.Value == "" {
			return nil, errors.New("invalid filter")
		}
		record.AddFilter(headerType, matchType, filter.Key, filter.Value)
	}

	targets := make([]eacl.Target, len(r.Targets))
	for i, target := range r.Targets {
		trgt, err := ToNativeTarget(target)
		if err != nil {
			return nil, err
		}
		targets[i] = *trgt
	}
	record.SetTargets(targets...)

	return &record, nil
}

// FromNativeRecord converts [eacl.Record] to appropriate [apiserver.Record].
func FromNativeRecord(r eacl.Record) (apiserver.Record, error) {
	var err error
	var record apiserver.Record

	record.Action, err = FromNativeAction(r.Action())
	if err != nil {
		return record, err
	}

	record.Operation, err = FromNativeOperation(r.Operation())
	if err != nil {
		return record, err
	}

	record.Filters = make([]apiserver.Filter, len(r.Filters()))
	for i, filter := range r.Filters() {
		headerType, err := FromNativeHeaderType(filter.From())
		if err != nil {
			return record, err
		}
		matchType, err := FromNativeMatchType(filter.Matcher())
		if err != nil {
			return record, err
		}

		record.Filters[i] = apiserver.Filter{
			HeaderType: headerType,
			Key:        filter.Key(),
			MatchType:  matchType,
			Value:      filter.Value(),
		}
	}

	record.Targets = make([]apiserver.Target, len(r.Targets()))
	for i, target := range r.Targets() {
		trgt, err := FromNativeTarget(target)
		if err != nil {
			return record, err
		}
		record.Targets[i] = trgt
	}

	return record, nil
}

// ToNativeTarget converts [apiserver.Target] to appropriate [eacl.Target].
func ToNativeTarget(t apiserver.Target) (*eacl.Target, error) {
	var target eacl.Target

	if len(t.Keys) > 0 && t.Role != apiserver.KEYS {
		return nil, fmt.Errorf("you cannot set binary keys with role other than '%s'", apiserver.KEYS)
	}

	role, err := ToNativeRole(t.Role)
	if err != nil {
		return nil, err
	}
	target.SetRole(role)

	keys := make([][]byte, len(t.Keys))
	for i, key := range t.Keys {
		binaryKey, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("couldn't decode target key: %w", err)
		}
		keys[i] = binaryKey
	}
	target.SetBinaryKeys(keys)

	return &target, nil
}

// FromNativeTarget converts [eacl.Target] to appropriate [apiserver.Target].
func FromNativeTarget(t eacl.Target) (apiserver.Target, error) {
	var err error
	var target apiserver.Target

	target.Role, err = FromNativeRole(t.Role())
	if err != nil {
		return target, err
	}

	target.Keys = make([]string, len(t.BinaryKeys()))
	for i, key := range t.BinaryKeys() {
		target.Keys[i] = hex.EncodeToString(key)
	}

	return target, nil
}

// ToNativeObjectToken converts [][apiserver.Record] to appropriate [bearer.Token].
func ToNativeObjectToken(tokenRecords []apiserver.Record) (*bearer.Token, error) {
	table, err := ToNativeTable(tokenRecords)
	if err != nil {
		return nil, err
	}

	var btoken bearer.Token
	btoken.SetEACLTable(*table)

	return &btoken, nil
}

// ToNativeTable converts records to [eacl.Table].
func ToNativeTable(records []apiserver.Record) (*eacl.Table, error) {
	table := eacl.NewTable()

	for _, rec := range records {
		record, err := ToNativeRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("couldn't transform record to native: %w", err)
		}
		table.AddRecord(record)
	}

	return table, nil
}

// ToNativeMatchFilter converts [apiserver.SearchMatch] to [object.SearchMatchType].
func ToNativeMatchFilter(s apiserver.SearchMatch) (object.SearchMatchType, error) {
	switch s {
	case apiserver.MatchStringEqual:
		return object.MatchStringEqual, nil
	case apiserver.MatchStringNotEqual:
		return object.MatchStringNotEqual, nil
	case apiserver.MatchNotPresent:
		return object.MatchNotPresent, nil
	case apiserver.MatchCommonPrefix:
		return object.MatchCommonPrefix, nil
	default:
		return object.MatchUnknown, fmt.Errorf("unsupported search match: '%s'", s)
	}
}

// ToNativeFilters converts [apiserver.SearchFilters] to [object.SearchFilters].
func ToNativeFilters(fs apiserver.SearchFilters) (object.SearchFilters, error) {
	filters := object.NewSearchFilters()
	filters.AddRootFilter()

	for _, f := range fs.Filters {
		matchFilter, err := ToNativeMatchFilter(f.Match)
		if err != nil {
			return nil, err
		}

		filters.AddFilter(f.Key, f.Value, matchFilter)
	}

	return filters, nil
}

// NewString returns pointer to provided string.
func NewString(val string) *string {
	return &val
}

// NewInteger returns pointer to provided int.
func NewInteger(val int64) *int64 {
	return &val
}

// NewSuccessResponse forms model.SuccessResponse.
func NewSuccessResponse() *apiserver.SuccessResponse {
	return &apiserver.SuccessResponse{
		Success: true,
	}
}

// NewErrorResponse forms [apiserver.ErrorResponse].
func NewErrorResponse(err error) *apiserver.ErrorResponse {
	var code uint32
	var statusErr apistatus.StatusV2
	t := apiserver.GW

	if errors.As(err, &statusErr) {
		code = uint32(statusErr.ErrorToV2().Code())
		t = apiserver.API
	}

	return &apiserver.ErrorResponse{
		Code:    code,
		Message: err.Error(),
		Type:    t,
	}
}
