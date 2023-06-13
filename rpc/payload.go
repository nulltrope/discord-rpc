// Package rpc contains payload definitions and util functions for interacting with a Discord RPC server.
package rpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Payload is a wrapper for data sent to and received from the Discord RPC server.
// See https://discord.com/developers/docs/topics/rpc#payloads-payload-structure.
//
// When sending payloads, Args should be a struct with JSON tags corresponding to the Cmd being sent.
// See https://discord.com/developers/docs/topics/rpc#commands-and-events-rpc-commands.
//
// When receiving payloads, only a shallow JSON unmarshal is performed.
// The caller can further unmarshal the RawData field based on the Cmd or Evt type.
// For Error payloads, data will automatically be unmarshalled and placed in the ErrorData field.
// See https://discord.com/developers/docs/topics/rpc#commands-and-events-rpc-events.
type Payload struct {
	Cmd   string      `json:"cmd"`
	Nonce string      `json:"nonce,omitempty"`
	Evt   string      `json:"evt,omitempty"`
	Args  interface{} `json:"args,omitempty"`
	// RawData let's consumer further decode JSON based on Cmd/Evt type.
	RawData *json.RawMessage `json:"data,omitempty"`
	// ErrorData contains ErrorEvtData if this payload is an error.
	ErrorData *ErrorEvtData `json:"-"`
}

// ErrorEvtData is received for error payloads.
// See https://discord.com/developers/docs/topics/rpc#error.
type ErrorEvtData struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type readyEvtDataConfig struct {
	CdnHost     string `json:"cdn_host"`
	ApiEndpoint string `json:"api_endpoint"`
	Environment string `json:"environment"`
}

type readyEvtDataUser struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	// Excluding optional info we don't care about
}

// ReadyEvtData is received for READY payloads.
// See https://discord.com/developers/docs/topics/rpc#ready.
type ReadyEvtData struct {
	V      int                `json:"v"`
	Config readyEvtDataConfig `json:"config"`
	User   readyEvtDataUser   `json:"user"`
}

// UnmarshalJSON is a custom unmarshaller for Payloads that will populate ErrorData if the Evt is ERROR.
func (p *Payload) UnmarshalJSON(data []byte) error {
	// Type alias prevents infinite unmarshal loop
	type PayloadAlias Payload

	var payload PayloadAlias
	err := json.Unmarshal(data, &payload)
	if err != nil {
		return err
	}

	if p.Evt == "ERROR" {
		var errData ErrorEvtData
		err = json.Unmarshal(*p.RawData, &errData)
		if err != nil {
			return fmt.Errorf("got error payload but couldn't unmarshal data: %v", err)
		}
		payload.ErrorData = &errData
	}

	*p = Payload(payload)
	return nil
}

// Error returns a formatted error message, if the payload is an error type.
func (p *Payload) Error() error {
	if p.ErrorData != nil {
		return fmt.Errorf("code:%d, message:%s", p.ErrorData.Code, p.ErrorData.Message)
	} else if p.Evt == "ERROR" {
		return errors.New("unknown")
	}
	return nil
}
