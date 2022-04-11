package handlers

import (
	"encoding/hex"
	"fmt"

	sessionv2 "github.com/nspcc-dev/neofs-api-go/v2/session"
	"github.com/nspcc-dev/neofs-rest-gw/gen/models"
	cid "github.com/nspcc-dev/neofs-sdk-go/container/id"
	"github.com/nspcc-dev/neofs-sdk-go/eacl"
	"github.com/nspcc-dev/neofs-sdk-go/session"
	"github.com/nspcc-dev/neofs-sdk-go/token"
)

// ToNativeAction converts models.Action to appropriate eacl.Action.
func ToNativeAction(a *models.Action) (eacl.Action, error) {
	if a == nil {
		return eacl.ActionUnknown, fmt.Errorf("unsupported empty action")
	}

	switch *a {
	case models.ActionALLOW:
		return eacl.ActionAllow, nil
	case models.ActionDENY:
		return eacl.ActionDeny, nil
	default:
		return eacl.ActionUnknown, fmt.Errorf("unsupported action type: '%s'", *a)
	}
}

// ToNativeOperation converts models.Operation to appropriate eacl.Operation.
func ToNativeOperation(o *models.Operation) (eacl.Operation, error) {
	if o == nil {
		return eacl.OperationUnknown, fmt.Errorf("unsupported empty opertaion")
	}

	switch *o {
	case models.OperationGET:
		return eacl.OperationGet, nil
	case models.OperationHEAD:
		return eacl.OperationHead, nil
	case models.OperationPUT:
		return eacl.OperationPut, nil
	case models.OperationDELETE:
		return eacl.OperationDelete, nil
	case models.OperationSEARCH:
		return eacl.OperationSearch, nil
	case models.OperationRANGE:
		return eacl.OperationRange, nil
	case models.OperationRANGEHASH:
		return eacl.OperationRangeHash, nil
	default:
		return eacl.OperationUnknown, fmt.Errorf("unsupported operation type: '%s'", *o)
	}
}

// ToNativeHeaderType converts models.HeaderType to appropriate eacl.FilterHeaderType.
func ToNativeHeaderType(h *models.HeaderType) (eacl.FilterHeaderType, error) {
	if h == nil {
		return eacl.HeaderTypeUnknown, fmt.Errorf("unsupported empty header type")
	}

	switch *h {
	case models.HeaderTypeOBJECT:
		return eacl.HeaderFromObject, nil
	case models.HeaderTypeREQUEST:
		return eacl.HeaderFromRequest, nil
	case models.HeaderTypeSERVICE:
		return eacl.HeaderFromService, nil
	default:
		return eacl.HeaderTypeUnknown, fmt.Errorf("unsupported header type: '%s'", *h)
	}
}

// ToNativeMatchType converts models.MatchType to appropriate eacl.Match.
func ToNativeMatchType(t *models.MatchType) (eacl.Match, error) {
	if t == nil {
		return eacl.MatchUnknown, fmt.Errorf("unsupported empty match type")
	}

	switch *t {
	case models.MatchTypeSTRINGEQUAL:
		return eacl.MatchStringEqual, nil
	case models.MatchTypeSTRINGNOTEQUAL:
		return eacl.MatchStringNotEqual, nil
	default:
		return eacl.MatchUnknown, fmt.Errorf("unsupported match type: '%s'", *t)
	}
}

// ToNativeRole converts models.Role to appropriate eacl.Role.
func ToNativeRole(r *models.Role) (eacl.Role, error) {
	if r == nil {
		return eacl.RoleUnknown, fmt.Errorf("unsupported empty role")
	}

	switch *r {
	case models.RoleUSER:
		return eacl.RoleUser, nil
	case models.RoleSYSTEM:
		return eacl.RoleSystem, nil
	case models.RoleOTHERS:
		return eacl.RoleOthers, nil
	default:
		return eacl.RoleUnknown, fmt.Errorf("unsupported role type: '%s'", *r)
	}
}

// ToNativeVerb converts models.Verb to appropriate session.ContainerSessionVerb.
func ToNativeVerb(r *models.Verb) (sessionv2.ContainerSessionVerb, error) {
	if r == nil {
		return sessionv2.ContainerVerbUnknown, fmt.Errorf("unsupported empty verb type")
	}

	switch *r {
	case models.VerbPUT:
		return sessionv2.ContainerVerbPut, nil
	case models.VerbDELETE:
		return sessionv2.ContainerVerbDelete, nil
	case models.VerbSETEACL:
		return sessionv2.ContainerVerbSetEACL, nil
	default:
		return sessionv2.ContainerVerbUnknown, fmt.Errorf("unsupported verb type: '%s'", *r)
	}
}

// ToNativeRule converts models.Rule to appropriate session.ContainerContext.
func ToNativeRule(r *models.Rule) (*session.ContainerContext, error) {
	var ctx session.ContainerContext

	verb, err := ToNativeVerb(r.Verb)
	if err != nil {
		return nil, err
	}
	ctx.ToV2().SetVerb(verb)

	if r.ContainerID == "" {
		ctx.ApplyTo(nil)
	} else {
		var cnrID cid.ID
		if err = cnrID.Parse(r.ContainerID); err != nil {
			return nil, fmt.Errorf("couldn't parse container id: %w", err)
		}
		ctx.ApplyTo(&cnrID)
	}

	return &ctx, nil
}

// ToNativeContainerToken converts models.Bearer to appropriate session.Token.
func ToNativeContainerToken(b *models.Bearer) (*session.Token, error) {
	sctx, err := ToNativeRule(b.Container)
	if err != nil {
		return nil, fmt.Errorf("couldn't transform rule to native: %w", err)
	}
	tok := session.NewToken()
	tok.SetContext(sctx)

	return tok, nil
}

// ToNativeRecord converts models.Record to appropriate eacl.Record.
func ToNativeRecord(r *models.Record) (*eacl.Record, error) {
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
		if filter.Key == nil || filter.Value == nil {
			return nil, fmt.Errorf("invalid filter")
		}
		record.AddFilter(headerType, matchType, *filter.Key, *filter.Value)
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

// ToNativeTarget converts models.Target to appropriate eacl.Target.
func ToNativeTarget(t *models.Target) (*eacl.Target, error) {
	var target eacl.Target

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

// ToNativeObjectToken converts Bearer to appropriate token.BearerToken.
func ToNativeObjectToken(b *models.Bearer) (*token.BearerToken, error) {
	var btoken token.BearerToken
	var table eacl.Table

	for _, rec := range b.Object {
		record, err := ToNativeRecord(rec)
		if err != nil {
			return nil, fmt.Errorf("couldn't transform record to native: %w", err)
		}
		table.AddRecord(record)
	}

	btoken.SetEACLTable(&table)

	return &btoken, nil
}
