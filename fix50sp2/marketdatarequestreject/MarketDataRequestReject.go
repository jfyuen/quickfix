//Package marketdatarequestreject msg type = Y.
package marketdatarequestreject

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

import (
	"github.com/quickfixgo/quickfix/fix/enum"
)

//Message is a MarketDataRequestReject wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//MDReqID is a required field for MarketDataRequestReject.
func (m Message) MDReqID() (*field.MDReqIDField, quickfix.MessageRejectError) {
	f := &field.MDReqIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMDReqID reads a MDReqID from MarketDataRequestReject.
func (m Message) GetMDReqID(f *field.MDReqIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MDReqRejReason is a non-required field for MarketDataRequestReject.
func (m Message) MDReqRejReason() (*field.MDReqRejReasonField, quickfix.MessageRejectError) {
	f := &field.MDReqRejReasonField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMDReqRejReason reads a MDReqRejReason from MarketDataRequestReject.
func (m Message) GetMDReqRejReason(f *field.MDReqRejReasonField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoAltMDSource is a non-required field for MarketDataRequestReject.
func (m Message) NoAltMDSource() (*field.NoAltMDSourceField, quickfix.MessageRejectError) {
	f := &field.NoAltMDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoAltMDSource reads a NoAltMDSource from MarketDataRequestReject.
func (m Message) GetNoAltMDSource(f *field.NoAltMDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for MarketDataRequestReject.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from MarketDataRequestReject.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedTextLen is a non-required field for MarketDataRequestReject.
func (m Message) EncodedTextLen() (*field.EncodedTextLenField, quickfix.MessageRejectError) {
	f := &field.EncodedTextLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedTextLen reads a EncodedTextLen from MarketDataRequestReject.
func (m Message) GetEncodedTextLen(f *field.EncodedTextLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedText is a non-required field for MarketDataRequestReject.
func (m Message) EncodedText() (*field.EncodedTextField, quickfix.MessageRejectError) {
	f := &field.EncodedTextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedText reads a EncodedText from MarketDataRequestReject.
func (m Message) GetEncodedText(f *field.EncodedTextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPartyIDs is a non-required field for MarketDataRequestReject.
func (m Message) NoPartyIDs() (*field.NoPartyIDsField, quickfix.MessageRejectError) {
	f := &field.NoPartyIDsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPartyIDs reads a NoPartyIDs from MarketDataRequestReject.
func (m Message) GetNoPartyIDs(f *field.NoPartyIDsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for MarketDataRequestReject.
func New(
	mdreqid *field.MDReqIDField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIXT11))
	builder.Header.Set(field.NewDefaultApplVerID(enum.ApplVerID_FIX50SP2))
	builder.Header.Set(field.NewMsgType("Y"))
	builder.Body.Set(mdreqid)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.ApplVerID_FIX50SP2, "Y", r
}
