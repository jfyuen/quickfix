//Package tradingsessionlistupdatereport msg type = BS.
package tradingsessionlistupdatereport

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/enum"
	"github.com/quickfixgo/quickfix/field"
)

//Message is a TradingSessionListUpdateReport wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//TradSesReqID is a non-required field for TradingSessionListUpdateReport.
func (m Message) TradSesReqID() (*field.TradSesReqIDField, quickfix.MessageRejectError) {
	f := &field.TradSesReqIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradSesReqID reads a TradSesReqID from TradingSessionListUpdateReport.
func (m Message) GetTradSesReqID(f *field.TradSesReqIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradSesUpdateAction is a non-required field for TradingSessionListUpdateReport.
func (m Message) TradSesUpdateAction() (*field.TradSesUpdateActionField, quickfix.MessageRejectError) {
	f := &field.TradSesUpdateActionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradSesUpdateAction reads a TradSesUpdateAction from TradingSessionListUpdateReport.
func (m Message) GetTradSesUpdateAction(f *field.TradSesUpdateActionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoTradingSessions is a required field for TradingSessionListUpdateReport.
func (m Message) NoTradingSessions() (*field.NoTradingSessionsField, quickfix.MessageRejectError) {
	f := &field.NoTradingSessionsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoTradingSessions reads a NoTradingSessions from TradingSessionListUpdateReport.
func (m Message) GetNoTradingSessions(f *field.NoTradingSessionsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ApplID is a non-required field for TradingSessionListUpdateReport.
func (m Message) ApplID() (*field.ApplIDField, quickfix.MessageRejectError) {
	f := &field.ApplIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetApplID reads a ApplID from TradingSessionListUpdateReport.
func (m Message) GetApplID(f *field.ApplIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ApplSeqNum is a non-required field for TradingSessionListUpdateReport.
func (m Message) ApplSeqNum() (*field.ApplSeqNumField, quickfix.MessageRejectError) {
	f := &field.ApplSeqNumField{}
	err := m.Body.Get(f)
	return f, err
}

//GetApplSeqNum reads a ApplSeqNum from TradingSessionListUpdateReport.
func (m Message) GetApplSeqNum(f *field.ApplSeqNumField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ApplLastSeqNum is a non-required field for TradingSessionListUpdateReport.
func (m Message) ApplLastSeqNum() (*field.ApplLastSeqNumField, quickfix.MessageRejectError) {
	f := &field.ApplLastSeqNumField{}
	err := m.Body.Get(f)
	return f, err
}

//GetApplLastSeqNum reads a ApplLastSeqNum from TradingSessionListUpdateReport.
func (m Message) GetApplLastSeqNum(f *field.ApplLastSeqNumField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ApplResendFlag is a non-required field for TradingSessionListUpdateReport.
func (m Message) ApplResendFlag() (*field.ApplResendFlagField, quickfix.MessageRejectError) {
	f := &field.ApplResendFlagField{}
	err := m.Body.Get(f)
	return f, err
}

//GetApplResendFlag reads a ApplResendFlag from TradingSessionListUpdateReport.
func (m Message) GetApplResendFlag(f *field.ApplResendFlagField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for TradingSessionListUpdateReport.
func New(
	notradingsessions *field.NoTradingSessionsField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(enum.BeginStringFIXT11))
	builder.Header.Set(field.NewDefaultApplVerID(enum.ApplVerID_FIX50SP1))
	builder.Header.Set(field.NewMsgType("BS"))
	builder.Body.Set(notradingsessions)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.ApplVerID_FIX50SP1, "BS", r
}
