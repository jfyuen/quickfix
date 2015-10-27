//Package networkcounterpartysystemstatusrequest msg type = BC.
package networkcounterpartysystemstatusrequest

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

//Message is a NetworkCounterpartySystemStatusRequest wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//NetworkRequestType is a required field for NetworkCounterpartySystemStatusRequest.
func (m Message) NetworkRequestType() (*field.NetworkRequestTypeField, quickfix.MessageRejectError) {
	f := &field.NetworkRequestTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNetworkRequestType reads a NetworkRequestType from NetworkCounterpartySystemStatusRequest.
func (m Message) GetNetworkRequestType(f *field.NetworkRequestTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NetworkRequestID is a required field for NetworkCounterpartySystemStatusRequest.
func (m Message) NetworkRequestID() (*field.NetworkRequestIDField, quickfix.MessageRejectError) {
	f := &field.NetworkRequestIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNetworkRequestID reads a NetworkRequestID from NetworkCounterpartySystemStatusRequest.
func (m Message) GetNetworkRequestID(f *field.NetworkRequestIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoCompIDs is a non-required field for NetworkCounterpartySystemStatusRequest.
func (m Message) NoCompIDs() (*field.NoCompIDsField, quickfix.MessageRejectError) {
	f := &field.NoCompIDsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoCompIDs reads a NoCompIDs from NetworkCounterpartySystemStatusRequest.
func (m Message) GetNoCompIDs(f *field.NoCompIDsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized MessageBuilder with specified required fields for NetworkCounterpartySystemStatusRequest.
func New(
	networkrequesttype *field.NetworkRequestTypeField,
	networkrequestid *field.NetworkRequestIDField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIX44))
	builder.Header.Set(field.NewMsgType("BC"))
	builder.Body.Set(networkrequesttype)
	builder.Body.Set(networkrequestid)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return fix.BeginString_FIX44, "BC", r
}
