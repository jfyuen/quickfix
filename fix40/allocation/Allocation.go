//Package allocation msg type = J.
package allocation

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

//Message is a Allocation wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//AllocID is a required field for Allocation.
func (m Message) AllocID() (*field.AllocIDField, quickfix.MessageRejectError) {
	f := &field.AllocIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAllocID reads a AllocID from Allocation.
func (m Message) GetAllocID(f *field.AllocIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AllocTransType is a required field for Allocation.
func (m Message) AllocTransType() (*field.AllocTransTypeField, quickfix.MessageRejectError) {
	f := &field.AllocTransTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAllocTransType reads a AllocTransType from Allocation.
func (m Message) GetAllocTransType(f *field.AllocTransTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RefAllocID is a non-required field for Allocation.
func (m Message) RefAllocID() (*field.RefAllocIDField, quickfix.MessageRejectError) {
	f := &field.RefAllocIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRefAllocID reads a RefAllocID from Allocation.
func (m Message) GetRefAllocID(f *field.RefAllocIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoOrders is a required field for Allocation.
func (m Message) NoOrders() (*field.NoOrdersField, quickfix.MessageRejectError) {
	f := &field.NoOrdersField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoOrders reads a NoOrders from Allocation.
func (m Message) GetNoOrders(f *field.NoOrdersField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoExecs is a non-required field for Allocation.
func (m Message) NoExecs() (*field.NoExecsField, quickfix.MessageRejectError) {
	f := &field.NoExecsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoExecs reads a NoExecs from Allocation.
func (m Message) GetNoExecs(f *field.NoExecsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Side is a required field for Allocation.
func (m Message) Side() (*field.SideField, quickfix.MessageRejectError) {
	f := &field.SideField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSide reads a Side from Allocation.
func (m Message) GetSide(f *field.SideField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Symbol is a required field for Allocation.
func (m Message) Symbol() (*field.SymbolField, quickfix.MessageRejectError) {
	f := &field.SymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbol reads a Symbol from Allocation.
func (m Message) GetSymbol(f *field.SymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SymbolSfx is a non-required field for Allocation.
func (m Message) SymbolSfx() (*field.SymbolSfxField, quickfix.MessageRejectError) {
	f := &field.SymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbolSfx reads a SymbolSfx from Allocation.
func (m Message) GetSymbolSfx(f *field.SymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityID is a non-required field for Allocation.
func (m Message) SecurityID() (*field.SecurityIDField, quickfix.MessageRejectError) {
	f := &field.SecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityID reads a SecurityID from Allocation.
func (m Message) GetSecurityID(f *field.SecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//IDSource is a non-required field for Allocation.
func (m Message) IDSource() (*field.IDSourceField, quickfix.MessageRejectError) {
	f := &field.IDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIDSource reads a IDSource from Allocation.
func (m Message) GetIDSource(f *field.IDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Issuer is a non-required field for Allocation.
func (m Message) Issuer() (*field.IssuerField, quickfix.MessageRejectError) {
	f := &field.IssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssuer reads a Issuer from Allocation.
func (m Message) GetIssuer(f *field.IssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityDesc is a non-required field for Allocation.
func (m Message) SecurityDesc() (*field.SecurityDescField, quickfix.MessageRejectError) {
	f := &field.SecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityDesc reads a SecurityDesc from Allocation.
func (m Message) GetSecurityDesc(f *field.SecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Shares is a required field for Allocation.
func (m Message) Shares() (*field.SharesField, quickfix.MessageRejectError) {
	f := &field.SharesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetShares reads a Shares from Allocation.
func (m Message) GetShares(f *field.SharesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AvgPx is a required field for Allocation.
func (m Message) AvgPx() (*field.AvgPxField, quickfix.MessageRejectError) {
	f := &field.AvgPxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAvgPx reads a AvgPx from Allocation.
func (m Message) GetAvgPx(f *field.AvgPxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Currency is a non-required field for Allocation.
func (m Message) Currency() (*field.CurrencyField, quickfix.MessageRejectError) {
	f := &field.CurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCurrency reads a Currency from Allocation.
func (m Message) GetCurrency(f *field.CurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AvgPrxPrecision is a non-required field for Allocation.
func (m Message) AvgPrxPrecision() (*field.AvgPrxPrecisionField, quickfix.MessageRejectError) {
	f := &field.AvgPrxPrecisionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAvgPrxPrecision reads a AvgPrxPrecision from Allocation.
func (m Message) GetAvgPrxPrecision(f *field.AvgPrxPrecisionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradeDate is a required field for Allocation.
func (m Message) TradeDate() (*field.TradeDateField, quickfix.MessageRejectError) {
	f := &field.TradeDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradeDate reads a TradeDate from Allocation.
func (m Message) GetTradeDate(f *field.TradeDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TransactTime is a non-required field for Allocation.
func (m Message) TransactTime() (*field.TransactTimeField, quickfix.MessageRejectError) {
	f := &field.TransactTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTransactTime reads a TransactTime from Allocation.
func (m Message) GetTransactTime(f *field.TransactTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlmntTyp is a non-required field for Allocation.
func (m Message) SettlmntTyp() (*field.SettlmntTypField, quickfix.MessageRejectError) {
	f := &field.SettlmntTypField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlmntTyp reads a SettlmntTyp from Allocation.
func (m Message) GetSettlmntTyp(f *field.SettlmntTypField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FutSettDate is a non-required field for Allocation.
func (m Message) FutSettDate() (*field.FutSettDateField, quickfix.MessageRejectError) {
	f := &field.FutSettDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFutSettDate reads a FutSettDate from Allocation.
func (m Message) GetFutSettDate(f *field.FutSettDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NetMoney is a non-required field for Allocation.
func (m Message) NetMoney() (*field.NetMoneyField, quickfix.MessageRejectError) {
	f := &field.NetMoneyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNetMoney reads a NetMoney from Allocation.
func (m Message) GetNetMoney(f *field.NetMoneyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoMiscFees is a non-required field for Allocation.
func (m Message) NoMiscFees() (*field.NoMiscFeesField, quickfix.MessageRejectError) {
	f := &field.NoMiscFeesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoMiscFees reads a NoMiscFees from Allocation.
func (m Message) GetNoMiscFees(f *field.NoMiscFeesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlCurrAmt is a non-required field for Allocation.
func (m Message) SettlCurrAmt() (*field.SettlCurrAmtField, quickfix.MessageRejectError) {
	f := &field.SettlCurrAmtField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlCurrAmt reads a SettlCurrAmt from Allocation.
func (m Message) GetSettlCurrAmt(f *field.SettlCurrAmtField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlCurrency is a non-required field for Allocation.
func (m Message) SettlCurrency() (*field.SettlCurrencyField, quickfix.MessageRejectError) {
	f := &field.SettlCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlCurrency reads a SettlCurrency from Allocation.
func (m Message) GetSettlCurrency(f *field.SettlCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OpenClose is a non-required field for Allocation.
func (m Message) OpenClose() (*field.OpenCloseField, quickfix.MessageRejectError) {
	f := &field.OpenCloseField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOpenClose reads a OpenClose from Allocation.
func (m Message) GetOpenClose(f *field.OpenCloseField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for Allocation.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from Allocation.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoAllocs is a required field for Allocation.
func (m Message) NoAllocs() (*field.NoAllocsField, quickfix.MessageRejectError) {
	f := &field.NoAllocsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoAllocs reads a NoAllocs from Allocation.
func (m Message) GetNoAllocs(f *field.NoAllocsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized MessageBuilder with specified required fields for Allocation.
func New(
	allocid *field.AllocIDField,
	alloctranstype *field.AllocTransTypeField,
	noorders *field.NoOrdersField,
	side *field.SideField,
	symbol *field.SymbolField,
	shares *field.SharesField,
	avgpx *field.AvgPxField,
	tradedate *field.TradeDateField,
	noallocs *field.NoAllocsField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIX40))
	builder.Header.Set(field.NewMsgType("J"))
	builder.Body.Set(allocid)
	builder.Body.Set(alloctranstype)
	builder.Body.Set(noorders)
	builder.Body.Set(side)
	builder.Body.Set(symbol)
	builder.Body.Set(shares)
	builder.Body.Set(avgpx)
	builder.Body.Set(tradedate)
	builder.Body.Set(noallocs)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return fix.BeginString_FIX40, "J", r
}
