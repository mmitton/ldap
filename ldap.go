// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"errors"
	"fmt"
	"github.com/baris/asn1-ber"
	"io/ioutil"
)

// LDAP Application Codes
const (
	ApplicationBindRequest           = 0
	ApplicationBindResponse          = 1
	ApplicationUnbindRequest         = 2
	ApplicationSearchRequest         = 3
	ApplicationSearchResultEntry     = 4
	ApplicationSearchResultDone      = 5
	ApplicationModifyRequest         = 6
	ApplicationModifyResponse        = 7
	ApplicationAddRequest            = 8
	ApplicationAddResponse           = 9
	ApplicationDelRequest            = 10
	ApplicationDelResponse           = 11
	ApplicationModifyDNRequest       = 12
	ApplicationModifyDNResponse      = 13
	ApplicationCompareRequest        = 14
	ApplicationCompareResponse       = 15
	ApplicationAbandonRequest        = 16
	ApplicationSearchResultReference = 19
	ApplicationExtendedRequest       = 23
	ApplicationExtendedResponse      = 24
)

var ApplicationMap = map[uint8]string{
	ApplicationBindRequest:           "Bind Request",
	ApplicationBindResponse:          "Bind Response",
	ApplicationUnbindRequest:         "Unbind Request",
	ApplicationSearchRequest:         "Search Request",
	ApplicationSearchResultEntry:     "Search Result Entry",
	ApplicationSearchResultDone:      "Search Result Done",
	ApplicationModifyRequest:         "Modify Request",
	ApplicationModifyResponse:        "Modify Response",
	ApplicationAddRequest:            "Add Request",
	ApplicationAddResponse:           "Add Response",
	ApplicationDelRequest:            "Del Request",
	ApplicationDelResponse:           "Del Response",
	ApplicationModifyDNRequest:       "Modify DN Request",
	ApplicationModifyDNResponse:      "Modify DN Response",
	ApplicationCompareRequest:        "Compare Request",
	ApplicationCompareResponse:       "Compare Response",
	ApplicationAbandonRequest:        "Abandon Request",
	ApplicationSearchResultReference: "Search Result Reference",
	ApplicationExtendedRequest:       "Extended Request",
	ApplicationExtendedResponse:      "Extended Response",
}

// LDAP Result Codes
const (
	LDAPResultSuccess                      = 0
	LDAPResultOperationsError              = 1
	LDAPResultProtocolError                = 2
	LDAPResultTimeLimitExceeded            = 3
	LDAPResultSizeLimitExceeded            = 4
	LDAPResultCompareFalse                 = 5
	LDAPResultCompareTrue                  = 6
	LDAPResultAuthMethodNotSupported       = 7
	LDAPResultStrongAuthRequired           = 8
	LDAPResultReferral                     = 10
	LDAPResultAdminLimitExceeded           = 11
	LDAPResultUnavailableCriticalExtension = 12
	LDAPResultConfidentialityRequired      = 13
	LDAPResultSaslBindInProgress           = 14
	LDAPResultNoSuchAttribute              = 16
	LDAPResultUndefinedAttributeType       = 17
	LDAPResultInappropriateMatching        = 18
	LDAPResultConstraintViolation          = 19
	LDAPResultAttributeOrValueExists       = 20
	LDAPResultInvalidAttributeSyntax       = 21
	LDAPResultNoSuchObject                 = 32
	LDAPResultAliasProblem                 = 33
	LDAPResultInvalidDNSyntax              = 34
	LDAPResultAliasDereferencingProblem    = 36
	LDAPResultInappropriateAuthentication  = 48
	LDAPResultInvalidCredentials           = 49
	LDAPResultInsufficientAccessRights     = 50
	LDAPResultBusy                         = 51
	LDAPResultUnavailable                  = 52
	LDAPResultUnwillingToPerform           = 53
	LDAPResultLoopDetect                   = 54
	LDAPResultNamingViolation              = 64
	LDAPResultObjectClassViolation         = 65
	LDAPResultNotAllowedOnNonLeaf          = 66
	LDAPResultNotAllowedOnRDN              = 67
	LDAPResultEntryAlreadyExists           = 68
	LDAPResultObjectClassModsProhibited    = 69
	LDAPResultAffectsMultipleDSAs          = 71
	LDAPResultOther                        = 80

	ErrorNetwork         = 200
	ErrorFilterCompile   = 201
	ErrorFilterDecompile = 202
	ErrorDebugging       = 203
)

var LDAPResultCodeMap = map[uint8]string{
	LDAPResultSuccess:                      "Success",
	LDAPResultOperationsError:              "Operations Error",
	LDAPResultProtocolError:                "Protocol Error",
	LDAPResultTimeLimitExceeded:            "Time Limit Exceeded",
	LDAPResultSizeLimitExceeded:            "Size Limit Exceeded",
	LDAPResultCompareFalse:                 "Compare False",
	LDAPResultCompareTrue:                  "Compare True",
	LDAPResultAuthMethodNotSupported:       "Auth Method Not Supported",
	LDAPResultStrongAuthRequired:           "Strong Auth Required",
	LDAPResultReferral:                     "Referral",
	LDAPResultAdminLimitExceeded:           "Admin Limit Exceeded",
	LDAPResultUnavailableCriticalExtension: "Unavailable Critical Extension",
	LDAPResultConfidentialityRequired:      "Confidentiality Required",
	LDAPResultSaslBindInProgress:           "Sasl Bind In Progress",
	LDAPResultNoSuchAttribute:              "No Such Attribute",
	LDAPResultUndefinedAttributeType:       "Undefined Attribute Type",
	LDAPResultInappropriateMatching:        "Inappropriate Matching",
	LDAPResultConstraintViolation:          "Constraint Violation",
	LDAPResultAttributeOrValueExists:       "Attribute Or Value Exists",
	LDAPResultInvalidAttributeSyntax:       "Invalid Attribute Syntax",
	LDAPResultNoSuchObject:                 "No Such Object",
	LDAPResultAliasProblem:                 "Alias Problem",
	LDAPResultInvalidDNSyntax:              "Invalid DN Syntax",
	LDAPResultAliasDereferencingProblem:    "Alias Dereferencing Problem",
	LDAPResultInappropriateAuthentication:  "Inappropriate Authentication",
	LDAPResultInvalidCredentials:           "Invalid Credentials",
	LDAPResultInsufficientAccessRights:     "Insufficient Access Rights",
	LDAPResultBusy:                         "Busy",
	LDAPResultUnavailable:                  "Unavailable",
	LDAPResultUnwillingToPerform:           "Unwilling To Perform",
	LDAPResultLoopDetect:                   "Loop Detect",
	LDAPResultNamingViolation:              "Naming Violation",
	LDAPResultObjectClassViolation:         "Object Class Violation",
	LDAPResultNotAllowedOnNonLeaf:          "Not Allowed On Non Leaf",
	LDAPResultNotAllowedOnRDN:              "Not Allowed On RDN",
	LDAPResultEntryAlreadyExists:           "Entry Already Exists",
	LDAPResultObjectClassModsProhibited:    "Object Class Mods Prohibited",
	LDAPResultAffectsMultipleDSAs:          "Affects Multiple DSAs",
	LDAPResultOther:                        "Other",
}

// Adds descriptions to an LDAP Response packet for debugging
func addLDAPDescriptions(packet *ber.Packet) (err *Error) {
	defer func() {
		if r := recover(); r != nil {
			err = NewError(ErrorDebugging, errors.New("Cannot process packet to add descriptions"))
		}
	}()
	packet.Description = "LDAP Response"
	packet.Children[0].Description = "Message ID"

	application := packet.Children[1].Tag
	packet.Children[1].Description = ApplicationMap[application]

	switch application {
	case ApplicationBindRequest:
		addRequestDescriptions(packet)
	case ApplicationBindResponse:
		addDefaultLDAPResponseDescriptions(packet)
	case ApplicationUnbindRequest:
		addRequestDescriptions(packet)
	case ApplicationSearchRequest:
		addRequestDescriptions(packet)
	case ApplicationSearchResultEntry:
		packet.Children[1].Children[0].Description = "Object Name"
		packet.Children[1].Children[1].Description = "Attributes"
		for _, child := range packet.Children[1].Children[1].Children {
			child.Description = "Attribute"
			child.Children[0].Description = "Attribute Name"
			child.Children[1].Description = "Attribute Values"
			for _, grandchild := range child.Children[1].Children {
				grandchild.Description = "Attribute Value"
			}
		}
		if len(packet.Children) == 3 {
			addControlDescriptions(packet.Children[2])
		}
	case ApplicationSearchResultDone:
		addDefaultLDAPResponseDescriptions(packet)
	case ApplicationModifyRequest:
		addRequestDescriptions(packet)
	case ApplicationModifyResponse:
	case ApplicationAddRequest:
		addRequestDescriptions(packet)
	case ApplicationAddResponse:
	case ApplicationDelRequest:
		addRequestDescriptions(packet)
	case ApplicationDelResponse:
	case ApplicationModifyDNRequest:
		addRequestDescriptions(packet)
	case ApplicationModifyDNResponse:
	case ApplicationCompareRequest:
		addRequestDescriptions(packet)
	case ApplicationCompareResponse:
	case ApplicationAbandonRequest:
		addRequestDescriptions(packet)
	case ApplicationSearchResultReference:
	case ApplicationExtendedRequest:
		addRequestDescriptions(packet)
	case ApplicationExtendedResponse:
	}

	return nil
}

func addControlDescriptions(packet *ber.Packet) {
	packet.Description = "Controls"
	for _, child := range packet.Children {
		child.Description = "Control"
		child.Children[0].Description = "Control Type (" + ControlTypeMap[child.Children[0].Value.(string)] + ")"
		value := child.Children[1]
		if len(child.Children) == 3 {
			child.Children[1].Description = "Criticality"
			value = child.Children[2]
		}
		value.Description = "Control Value"

		switch child.Children[0].Value.(string) {
		case ControlTypePaging:
			value.Description += " (Paging)"
			if value.Value != nil {
				value_children := ber.DecodePacket(value.Data.Bytes())
				value.Data.Truncate(0)
				value.Value = nil
				value_children.Children[1].Value = value_children.Children[1].Data.Bytes()
				value.AppendChild(value_children)
			}
			value.Children[0].Description = "Real Search Control Value"
			value.Children[0].Children[0].Description = "Paging Size"
			value.Children[0].Children[1].Description = "Cookie"
		}
	}
}

func addRequestDescriptions(packet *ber.Packet) {
	packet.Description = "LDAP Request"
	packet.Children[0].Description = "Message ID"
	packet.Children[1].Description = ApplicationMap[packet.Children[1].Tag]
	if len(packet.Children) == 3 {
		addControlDescriptions(packet.Children[2])
	}
}

func addDefaultLDAPResponseDescriptions(packet *ber.Packet) {
	resultCode := packet.Children[1].Children[0].Value.(uint64)
	packet.Children[1].Children[0].Description = "Result Code (" + LDAPResultCodeMap[uint8(resultCode)] + ")"
	packet.Children[1].Children[1].Description = "Matched DN"
	packet.Children[1].Children[2].Description = "Error Message"
	if len(packet.Children[1].Children) > 3 {
		packet.Children[1].Children[3].Description = "Referral"
	}
	if len(packet.Children) == 3 {
		addControlDescriptions(packet.Children[2])
	}
}

func DebugBinaryFile(FileName string) *Error {
	file, err := ioutil.ReadFile(FileName)
	if err != nil {
		return NewError(ErrorDebugging, err)
	}
	ber.PrintBytes(file, "")
	packet := ber.DecodePacket(file)
	addLDAPDescriptions(packet)
	ber.PrintPacket(packet)

	return nil
}

type Error struct {
	Err        error
	ResultCode uint8
}

func (e *Error) String() string {
	return fmt.Sprintf("LDAP Result Code %d %q: %s", e.ResultCode, LDAPResultCodeMap[e.ResultCode], e.Err)
}

func NewError(ResultCode uint8, Err error) *Error {
	return &Error{ResultCode: ResultCode, Err: Err}
}

func getLDAPResultCode(p *ber.Packet) (code uint8, description string) {
	if len(p.Children) >= 2 {
		response := p.Children[1]
		if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed && len(response.Children) == 3 {
			code = uint8(response.Children[0].Value.(uint64))
			description = response.Children[2].Value.(string)
			return
		}
	}

	code = ErrorNetwork
	description = "Invalid packet format"
	return
}
