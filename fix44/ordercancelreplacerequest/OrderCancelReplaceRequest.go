//Package ordercancelreplacerequest msg type = G.
package ordercancelreplacerequest

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/enum"
	"github.com/quickfixgo/quickfix/field"
)

//Message is a OrderCancelReplaceRequest wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//OrderID is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderID() (*field.OrderIDField, quickfix.MessageRejectError) {
	f := &field.OrderIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderID reads a OrderID from OrderCancelReplaceRequest.
func (m Message) GetOrderID(f *field.OrderIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPartyIDs is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoPartyIDs() (*field.NoPartyIDsField, quickfix.MessageRejectError) {
	f := &field.NoPartyIDsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPartyIDs reads a NoPartyIDs from OrderCancelReplaceRequest.
func (m Message) GetNoPartyIDs(f *field.NoPartyIDsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradeOriginationDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) TradeOriginationDate() (*field.TradeOriginationDateField, quickfix.MessageRejectError) {
	f := &field.TradeOriginationDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradeOriginationDate reads a TradeOriginationDate from OrderCancelReplaceRequest.
func (m Message) GetTradeOriginationDate(f *field.TradeOriginationDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradeDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) TradeDate() (*field.TradeDateField, quickfix.MessageRejectError) {
	f := &field.TradeDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradeDate reads a TradeDate from OrderCancelReplaceRequest.
func (m Message) GetTradeDate(f *field.TradeDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrigClOrdID is a required field for OrderCancelReplaceRequest.
func (m Message) OrigClOrdID() (*field.OrigClOrdIDField, quickfix.MessageRejectError) {
	f := &field.OrigClOrdIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrigClOrdID reads a OrigClOrdID from OrderCancelReplaceRequest.
func (m Message) GetOrigClOrdID(f *field.OrigClOrdIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClOrdID is a required field for OrderCancelReplaceRequest.
func (m Message) ClOrdID() (*field.ClOrdIDField, quickfix.MessageRejectError) {
	f := &field.ClOrdIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClOrdID reads a ClOrdID from OrderCancelReplaceRequest.
func (m Message) GetClOrdID(f *field.ClOrdIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecondaryClOrdID is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecondaryClOrdID() (*field.SecondaryClOrdIDField, quickfix.MessageRejectError) {
	f := &field.SecondaryClOrdIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecondaryClOrdID reads a SecondaryClOrdID from OrderCancelReplaceRequest.
func (m Message) GetSecondaryClOrdID(f *field.SecondaryClOrdIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClOrdLinkID is a non-required field for OrderCancelReplaceRequest.
func (m Message) ClOrdLinkID() (*field.ClOrdLinkIDField, quickfix.MessageRejectError) {
	f := &field.ClOrdLinkIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClOrdLinkID reads a ClOrdLinkID from OrderCancelReplaceRequest.
func (m Message) GetClOrdLinkID(f *field.ClOrdLinkIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ListID is a non-required field for OrderCancelReplaceRequest.
func (m Message) ListID() (*field.ListIDField, quickfix.MessageRejectError) {
	f := &field.ListIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetListID reads a ListID from OrderCancelReplaceRequest.
func (m Message) GetListID(f *field.ListIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrigOrdModTime is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrigOrdModTime() (*field.OrigOrdModTimeField, quickfix.MessageRejectError) {
	f := &field.OrigOrdModTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrigOrdModTime reads a OrigOrdModTime from OrderCancelReplaceRequest.
func (m Message) GetOrigOrdModTime(f *field.OrigOrdModTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Account is a non-required field for OrderCancelReplaceRequest.
func (m Message) Account() (*field.AccountField, quickfix.MessageRejectError) {
	f := &field.AccountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccount reads a Account from OrderCancelReplaceRequest.
func (m Message) GetAccount(f *field.AccountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AcctIDSource is a non-required field for OrderCancelReplaceRequest.
func (m Message) AcctIDSource() (*field.AcctIDSourceField, quickfix.MessageRejectError) {
	f := &field.AcctIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAcctIDSource reads a AcctIDSource from OrderCancelReplaceRequest.
func (m Message) GetAcctIDSource(f *field.AcctIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AccountType is a non-required field for OrderCancelReplaceRequest.
func (m Message) AccountType() (*field.AccountTypeField, quickfix.MessageRejectError) {
	f := &field.AccountTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccountType reads a AccountType from OrderCancelReplaceRequest.
func (m Message) GetAccountType(f *field.AccountTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DayBookingInst is a non-required field for OrderCancelReplaceRequest.
func (m Message) DayBookingInst() (*field.DayBookingInstField, quickfix.MessageRejectError) {
	f := &field.DayBookingInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDayBookingInst reads a DayBookingInst from OrderCancelReplaceRequest.
func (m Message) GetDayBookingInst(f *field.DayBookingInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BookingUnit is a non-required field for OrderCancelReplaceRequest.
func (m Message) BookingUnit() (*field.BookingUnitField, quickfix.MessageRejectError) {
	f := &field.BookingUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBookingUnit reads a BookingUnit from OrderCancelReplaceRequest.
func (m Message) GetBookingUnit(f *field.BookingUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PreallocMethod is a non-required field for OrderCancelReplaceRequest.
func (m Message) PreallocMethod() (*field.PreallocMethodField, quickfix.MessageRejectError) {
	f := &field.PreallocMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPreallocMethod reads a PreallocMethod from OrderCancelReplaceRequest.
func (m Message) GetPreallocMethod(f *field.PreallocMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AllocID is a non-required field for OrderCancelReplaceRequest.
func (m Message) AllocID() (*field.AllocIDField, quickfix.MessageRejectError) {
	f := &field.AllocIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAllocID reads a AllocID from OrderCancelReplaceRequest.
func (m Message) GetAllocID(f *field.AllocIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoAllocs is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoAllocs() (*field.NoAllocsField, quickfix.MessageRejectError) {
	f := &field.NoAllocsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoAllocs reads a NoAllocs from OrderCancelReplaceRequest.
func (m Message) GetNoAllocs(f *field.NoAllocsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlType is a non-required field for OrderCancelReplaceRequest.
func (m Message) SettlType() (*field.SettlTypeField, quickfix.MessageRejectError) {
	f := &field.SettlTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlType reads a SettlType from OrderCancelReplaceRequest.
func (m Message) GetSettlType(f *field.SettlTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) SettlDate() (*field.SettlDateField, quickfix.MessageRejectError) {
	f := &field.SettlDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlDate reads a SettlDate from OrderCancelReplaceRequest.
func (m Message) GetSettlDate(f *field.SettlDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CashMargin is a non-required field for OrderCancelReplaceRequest.
func (m Message) CashMargin() (*field.CashMarginField, quickfix.MessageRejectError) {
	f := &field.CashMarginField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCashMargin reads a CashMargin from OrderCancelReplaceRequest.
func (m Message) GetCashMargin(f *field.CashMarginField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClearingFeeIndicator is a non-required field for OrderCancelReplaceRequest.
func (m Message) ClearingFeeIndicator() (*field.ClearingFeeIndicatorField, quickfix.MessageRejectError) {
	f := &field.ClearingFeeIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClearingFeeIndicator reads a ClearingFeeIndicator from OrderCancelReplaceRequest.
func (m Message) GetClearingFeeIndicator(f *field.ClearingFeeIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//HandlInst is a non-required field for OrderCancelReplaceRequest.
func (m Message) HandlInst() (*field.HandlInstField, quickfix.MessageRejectError) {
	f := &field.HandlInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetHandlInst reads a HandlInst from OrderCancelReplaceRequest.
func (m Message) GetHandlInst(f *field.HandlInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExecInst is a non-required field for OrderCancelReplaceRequest.
func (m Message) ExecInst() (*field.ExecInstField, quickfix.MessageRejectError) {
	f := &field.ExecInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExecInst reads a ExecInst from OrderCancelReplaceRequest.
func (m Message) GetExecInst(f *field.ExecInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MinQty is a non-required field for OrderCancelReplaceRequest.
func (m Message) MinQty() (*field.MinQtyField, quickfix.MessageRejectError) {
	f := &field.MinQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMinQty reads a MinQty from OrderCancelReplaceRequest.
func (m Message) GetMinQty(f *field.MinQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaxFloor is a non-required field for OrderCancelReplaceRequest.
func (m Message) MaxFloor() (*field.MaxFloorField, quickfix.MessageRejectError) {
	f := &field.MaxFloorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaxFloor reads a MaxFloor from OrderCancelReplaceRequest.
func (m Message) GetMaxFloor(f *field.MaxFloorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExDestination is a non-required field for OrderCancelReplaceRequest.
func (m Message) ExDestination() (*field.ExDestinationField, quickfix.MessageRejectError) {
	f := &field.ExDestinationField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExDestination reads a ExDestination from OrderCancelReplaceRequest.
func (m Message) GetExDestination(f *field.ExDestinationField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoTradingSessions is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoTradingSessions() (*field.NoTradingSessionsField, quickfix.MessageRejectError) {
	f := &field.NoTradingSessionsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoTradingSessions reads a NoTradingSessions from OrderCancelReplaceRequest.
func (m Message) GetNoTradingSessions(f *field.NoTradingSessionsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Symbol is a non-required field for OrderCancelReplaceRequest.
func (m Message) Symbol() (*field.SymbolField, quickfix.MessageRejectError) {
	f := &field.SymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbol reads a Symbol from OrderCancelReplaceRequest.
func (m Message) GetSymbol(f *field.SymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SymbolSfx is a non-required field for OrderCancelReplaceRequest.
func (m Message) SymbolSfx() (*field.SymbolSfxField, quickfix.MessageRejectError) {
	f := &field.SymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbolSfx reads a SymbolSfx from OrderCancelReplaceRequest.
func (m Message) GetSymbolSfx(f *field.SymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityID is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecurityID() (*field.SecurityIDField, quickfix.MessageRejectError) {
	f := &field.SecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityID reads a SecurityID from OrderCancelReplaceRequest.
func (m Message) GetSecurityID(f *field.SecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityIDSource is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecurityIDSource() (*field.SecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.SecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityIDSource reads a SecurityIDSource from OrderCancelReplaceRequest.
func (m Message) GetSecurityIDSource(f *field.SecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoSecurityAltID is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoSecurityAltID() (*field.NoSecurityAltIDField, quickfix.MessageRejectError) {
	f := &field.NoSecurityAltIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoSecurityAltID reads a NoSecurityAltID from OrderCancelReplaceRequest.
func (m Message) GetNoSecurityAltID(f *field.NoSecurityAltIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Product is a non-required field for OrderCancelReplaceRequest.
func (m Message) Product() (*field.ProductField, quickfix.MessageRejectError) {
	f := &field.ProductField{}
	err := m.Body.Get(f)
	return f, err
}

//GetProduct reads a Product from OrderCancelReplaceRequest.
func (m Message) GetProduct(f *field.ProductField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CFICode is a non-required field for OrderCancelReplaceRequest.
func (m Message) CFICode() (*field.CFICodeField, quickfix.MessageRejectError) {
	f := &field.CFICodeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCFICode reads a CFICode from OrderCancelReplaceRequest.
func (m Message) GetCFICode(f *field.CFICodeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityType is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecurityType() (*field.SecurityTypeField, quickfix.MessageRejectError) {
	f := &field.SecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityType reads a SecurityType from OrderCancelReplaceRequest.
func (m Message) GetSecurityType(f *field.SecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecuritySubType is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecuritySubType() (*field.SecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.SecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecuritySubType reads a SecuritySubType from OrderCancelReplaceRequest.
func (m Message) GetSecuritySubType(f *field.SecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityMonthYear is a non-required field for OrderCancelReplaceRequest.
func (m Message) MaturityMonthYear() (*field.MaturityMonthYearField, quickfix.MessageRejectError) {
	f := &field.MaturityMonthYearField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityMonthYear reads a MaturityMonthYear from OrderCancelReplaceRequest.
func (m Message) GetMaturityMonthYear(f *field.MaturityMonthYearField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) MaturityDate() (*field.MaturityDateField, quickfix.MessageRejectError) {
	f := &field.MaturityDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityDate reads a MaturityDate from OrderCancelReplaceRequest.
func (m Message) GetMaturityDate(f *field.MaturityDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponPaymentDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) CouponPaymentDate() (*field.CouponPaymentDateField, quickfix.MessageRejectError) {
	f := &field.CouponPaymentDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponPaymentDate reads a CouponPaymentDate from OrderCancelReplaceRequest.
func (m Message) GetCouponPaymentDate(f *field.CouponPaymentDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//IssueDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) IssueDate() (*field.IssueDateField, quickfix.MessageRejectError) {
	f := &field.IssueDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssueDate reads a IssueDate from OrderCancelReplaceRequest.
func (m Message) GetIssueDate(f *field.IssueDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepoCollateralSecurityType is a non-required field for OrderCancelReplaceRequest.
func (m Message) RepoCollateralSecurityType() (*field.RepoCollateralSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.RepoCollateralSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepoCollateralSecurityType reads a RepoCollateralSecurityType from OrderCancelReplaceRequest.
func (m Message) GetRepoCollateralSecurityType(f *field.RepoCollateralSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseTerm is a non-required field for OrderCancelReplaceRequest.
func (m Message) RepurchaseTerm() (*field.RepurchaseTermField, quickfix.MessageRejectError) {
	f := &field.RepurchaseTermField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseTerm reads a RepurchaseTerm from OrderCancelReplaceRequest.
func (m Message) GetRepurchaseTerm(f *field.RepurchaseTermField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseRate is a non-required field for OrderCancelReplaceRequest.
func (m Message) RepurchaseRate() (*field.RepurchaseRateField, quickfix.MessageRejectError) {
	f := &field.RepurchaseRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseRate reads a RepurchaseRate from OrderCancelReplaceRequest.
func (m Message) GetRepurchaseRate(f *field.RepurchaseRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Factor is a non-required field for OrderCancelReplaceRequest.
func (m Message) Factor() (*field.FactorField, quickfix.MessageRejectError) {
	f := &field.FactorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFactor reads a Factor from OrderCancelReplaceRequest.
func (m Message) GetFactor(f *field.FactorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CreditRating is a non-required field for OrderCancelReplaceRequest.
func (m Message) CreditRating() (*field.CreditRatingField, quickfix.MessageRejectError) {
	f := &field.CreditRatingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCreditRating reads a CreditRating from OrderCancelReplaceRequest.
func (m Message) GetCreditRating(f *field.CreditRatingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InstrRegistry is a non-required field for OrderCancelReplaceRequest.
func (m Message) InstrRegistry() (*field.InstrRegistryField, quickfix.MessageRejectError) {
	f := &field.InstrRegistryField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInstrRegistry reads a InstrRegistry from OrderCancelReplaceRequest.
func (m Message) GetInstrRegistry(f *field.InstrRegistryField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CountryOfIssue is a non-required field for OrderCancelReplaceRequest.
func (m Message) CountryOfIssue() (*field.CountryOfIssueField, quickfix.MessageRejectError) {
	f := &field.CountryOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCountryOfIssue reads a CountryOfIssue from OrderCancelReplaceRequest.
func (m Message) GetCountryOfIssue(f *field.CountryOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StateOrProvinceOfIssue is a non-required field for OrderCancelReplaceRequest.
func (m Message) StateOrProvinceOfIssue() (*field.StateOrProvinceOfIssueField, quickfix.MessageRejectError) {
	f := &field.StateOrProvinceOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStateOrProvinceOfIssue reads a StateOrProvinceOfIssue from OrderCancelReplaceRequest.
func (m Message) GetStateOrProvinceOfIssue(f *field.StateOrProvinceOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//LocaleOfIssue is a non-required field for OrderCancelReplaceRequest.
func (m Message) LocaleOfIssue() (*field.LocaleOfIssueField, quickfix.MessageRejectError) {
	f := &field.LocaleOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetLocaleOfIssue reads a LocaleOfIssue from OrderCancelReplaceRequest.
func (m Message) GetLocaleOfIssue(f *field.LocaleOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RedemptionDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) RedemptionDate() (*field.RedemptionDateField, quickfix.MessageRejectError) {
	f := &field.RedemptionDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRedemptionDate reads a RedemptionDate from OrderCancelReplaceRequest.
func (m Message) GetRedemptionDate(f *field.RedemptionDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePrice is a non-required field for OrderCancelReplaceRequest.
func (m Message) StrikePrice() (*field.StrikePriceField, quickfix.MessageRejectError) {
	f := &field.StrikePriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePrice reads a StrikePrice from OrderCancelReplaceRequest.
func (m Message) GetStrikePrice(f *field.StrikePriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeCurrency is a non-required field for OrderCancelReplaceRequest.
func (m Message) StrikeCurrency() (*field.StrikeCurrencyField, quickfix.MessageRejectError) {
	f := &field.StrikeCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeCurrency reads a StrikeCurrency from OrderCancelReplaceRequest.
func (m Message) GetStrikeCurrency(f *field.StrikeCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptAttribute is a non-required field for OrderCancelReplaceRequest.
func (m Message) OptAttribute() (*field.OptAttributeField, quickfix.MessageRejectError) {
	f := &field.OptAttributeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptAttribute reads a OptAttribute from OrderCancelReplaceRequest.
func (m Message) GetOptAttribute(f *field.OptAttributeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractMultiplier is a non-required field for OrderCancelReplaceRequest.
func (m Message) ContractMultiplier() (*field.ContractMultiplierField, quickfix.MessageRejectError) {
	f := &field.ContractMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractMultiplier reads a ContractMultiplier from OrderCancelReplaceRequest.
func (m Message) GetContractMultiplier(f *field.ContractMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponRate is a non-required field for OrderCancelReplaceRequest.
func (m Message) CouponRate() (*field.CouponRateField, quickfix.MessageRejectError) {
	f := &field.CouponRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponRate reads a CouponRate from OrderCancelReplaceRequest.
func (m Message) GetCouponRate(f *field.CouponRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityExchange is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecurityExchange() (*field.SecurityExchangeField, quickfix.MessageRejectError) {
	f := &field.SecurityExchangeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityExchange reads a SecurityExchange from OrderCancelReplaceRequest.
func (m Message) GetSecurityExchange(f *field.SecurityExchangeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Issuer is a non-required field for OrderCancelReplaceRequest.
func (m Message) Issuer() (*field.IssuerField, quickfix.MessageRejectError) {
	f := &field.IssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssuer reads a Issuer from OrderCancelReplaceRequest.
func (m Message) GetIssuer(f *field.IssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuerLen is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedIssuerLen() (*field.EncodedIssuerLenField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuerLen reads a EncodedIssuerLen from OrderCancelReplaceRequest.
func (m Message) GetEncodedIssuerLen(f *field.EncodedIssuerLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuer is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedIssuer() (*field.EncodedIssuerField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuer reads a EncodedIssuer from OrderCancelReplaceRequest.
func (m Message) GetEncodedIssuer(f *field.EncodedIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityDesc is a non-required field for OrderCancelReplaceRequest.
func (m Message) SecurityDesc() (*field.SecurityDescField, quickfix.MessageRejectError) {
	f := &field.SecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityDesc reads a SecurityDesc from OrderCancelReplaceRequest.
func (m Message) GetSecurityDesc(f *field.SecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDescLen is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedSecurityDescLen() (*field.EncodedSecurityDescLenField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDescLen reads a EncodedSecurityDescLen from OrderCancelReplaceRequest.
func (m Message) GetEncodedSecurityDescLen(f *field.EncodedSecurityDescLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDesc is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedSecurityDesc() (*field.EncodedSecurityDescField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDesc reads a EncodedSecurityDesc from OrderCancelReplaceRequest.
func (m Message) GetEncodedSecurityDesc(f *field.EncodedSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Pool is a non-required field for OrderCancelReplaceRequest.
func (m Message) Pool() (*field.PoolField, quickfix.MessageRejectError) {
	f := &field.PoolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPool reads a Pool from OrderCancelReplaceRequest.
func (m Message) GetPool(f *field.PoolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractSettlMonth is a non-required field for OrderCancelReplaceRequest.
func (m Message) ContractSettlMonth() (*field.ContractSettlMonthField, quickfix.MessageRejectError) {
	f := &field.ContractSettlMonthField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractSettlMonth reads a ContractSettlMonth from OrderCancelReplaceRequest.
func (m Message) GetContractSettlMonth(f *field.ContractSettlMonthField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPProgram is a non-required field for OrderCancelReplaceRequest.
func (m Message) CPProgram() (*field.CPProgramField, quickfix.MessageRejectError) {
	f := &field.CPProgramField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPProgram reads a CPProgram from OrderCancelReplaceRequest.
func (m Message) GetCPProgram(f *field.CPProgramField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPRegType is a non-required field for OrderCancelReplaceRequest.
func (m Message) CPRegType() (*field.CPRegTypeField, quickfix.MessageRejectError) {
	f := &field.CPRegTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPRegType reads a CPRegType from OrderCancelReplaceRequest.
func (m Message) GetCPRegType(f *field.CPRegTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoEvents is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoEvents() (*field.NoEventsField, quickfix.MessageRejectError) {
	f := &field.NoEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoEvents reads a NoEvents from OrderCancelReplaceRequest.
func (m Message) GetNoEvents(f *field.NoEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DatedDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) DatedDate() (*field.DatedDateField, quickfix.MessageRejectError) {
	f := &field.DatedDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDatedDate reads a DatedDate from OrderCancelReplaceRequest.
func (m Message) GetDatedDate(f *field.DatedDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InterestAccrualDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) InterestAccrualDate() (*field.InterestAccrualDateField, quickfix.MessageRejectError) {
	f := &field.InterestAccrualDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInterestAccrualDate reads a InterestAccrualDate from OrderCancelReplaceRequest.
func (m Message) GetInterestAccrualDate(f *field.InterestAccrualDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementDesc is a non-required field for OrderCancelReplaceRequest.
func (m Message) AgreementDesc() (*field.AgreementDescField, quickfix.MessageRejectError) {
	f := &field.AgreementDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementDesc reads a AgreementDesc from OrderCancelReplaceRequest.
func (m Message) GetAgreementDesc(f *field.AgreementDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementID is a non-required field for OrderCancelReplaceRequest.
func (m Message) AgreementID() (*field.AgreementIDField, quickfix.MessageRejectError) {
	f := &field.AgreementIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementID reads a AgreementID from OrderCancelReplaceRequest.
func (m Message) GetAgreementID(f *field.AgreementIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) AgreementDate() (*field.AgreementDateField, quickfix.MessageRejectError) {
	f := &field.AgreementDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementDate reads a AgreementDate from OrderCancelReplaceRequest.
func (m Message) GetAgreementDate(f *field.AgreementDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementCurrency is a non-required field for OrderCancelReplaceRequest.
func (m Message) AgreementCurrency() (*field.AgreementCurrencyField, quickfix.MessageRejectError) {
	f := &field.AgreementCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementCurrency reads a AgreementCurrency from OrderCancelReplaceRequest.
func (m Message) GetAgreementCurrency(f *field.AgreementCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TerminationType is a non-required field for OrderCancelReplaceRequest.
func (m Message) TerminationType() (*field.TerminationTypeField, quickfix.MessageRejectError) {
	f := &field.TerminationTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTerminationType reads a TerminationType from OrderCancelReplaceRequest.
func (m Message) GetTerminationType(f *field.TerminationTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StartDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) StartDate() (*field.StartDateField, quickfix.MessageRejectError) {
	f := &field.StartDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStartDate reads a StartDate from OrderCancelReplaceRequest.
func (m Message) GetStartDate(f *field.StartDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EndDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) EndDate() (*field.EndDateField, quickfix.MessageRejectError) {
	f := &field.EndDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEndDate reads a EndDate from OrderCancelReplaceRequest.
func (m Message) GetEndDate(f *field.EndDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DeliveryType is a non-required field for OrderCancelReplaceRequest.
func (m Message) DeliveryType() (*field.DeliveryTypeField, quickfix.MessageRejectError) {
	f := &field.DeliveryTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDeliveryType reads a DeliveryType from OrderCancelReplaceRequest.
func (m Message) GetDeliveryType(f *field.DeliveryTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MarginRatio is a non-required field for OrderCancelReplaceRequest.
func (m Message) MarginRatio() (*field.MarginRatioField, quickfix.MessageRejectError) {
	f := &field.MarginRatioField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMarginRatio reads a MarginRatio from OrderCancelReplaceRequest.
func (m Message) GetMarginRatio(f *field.MarginRatioField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUnderlyings is a non-required field for OrderCancelReplaceRequest.
func (m Message) NoUnderlyings() (*field.NoUnderlyingsField, quickfix.MessageRejectError) {
	f := &field.NoUnderlyingsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUnderlyings reads a NoUnderlyings from OrderCancelReplaceRequest.
func (m Message) GetNoUnderlyings(f *field.NoUnderlyingsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Side is a required field for OrderCancelReplaceRequest.
func (m Message) Side() (*field.SideField, quickfix.MessageRejectError) {
	f := &field.SideField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSide reads a Side from OrderCancelReplaceRequest.
func (m Message) GetSide(f *field.SideField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TransactTime is a required field for OrderCancelReplaceRequest.
func (m Message) TransactTime() (*field.TransactTimeField, quickfix.MessageRejectError) {
	f := &field.TransactTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTransactTime reads a TransactTime from OrderCancelReplaceRequest.
func (m Message) GetTransactTime(f *field.TransactTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//QtyType is a non-required field for OrderCancelReplaceRequest.
func (m Message) QtyType() (*field.QtyTypeField, quickfix.MessageRejectError) {
	f := &field.QtyTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetQtyType reads a QtyType from OrderCancelReplaceRequest.
func (m Message) GetQtyType(f *field.QtyTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderQty is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderQty() (*field.OrderQtyField, quickfix.MessageRejectError) {
	f := &field.OrderQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderQty reads a OrderQty from OrderCancelReplaceRequest.
func (m Message) GetOrderQty(f *field.OrderQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CashOrderQty is a non-required field for OrderCancelReplaceRequest.
func (m Message) CashOrderQty() (*field.CashOrderQtyField, quickfix.MessageRejectError) {
	f := &field.CashOrderQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCashOrderQty reads a CashOrderQty from OrderCancelReplaceRequest.
func (m Message) GetCashOrderQty(f *field.CashOrderQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderPercent is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderPercent() (*field.OrderPercentField, quickfix.MessageRejectError) {
	f := &field.OrderPercentField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderPercent reads a OrderPercent from OrderCancelReplaceRequest.
func (m Message) GetOrderPercent(f *field.OrderPercentField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RoundingDirection is a non-required field for OrderCancelReplaceRequest.
func (m Message) RoundingDirection() (*field.RoundingDirectionField, quickfix.MessageRejectError) {
	f := &field.RoundingDirectionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRoundingDirection reads a RoundingDirection from OrderCancelReplaceRequest.
func (m Message) GetRoundingDirection(f *field.RoundingDirectionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RoundingModulus is a non-required field for OrderCancelReplaceRequest.
func (m Message) RoundingModulus() (*field.RoundingModulusField, quickfix.MessageRejectError) {
	f := &field.RoundingModulusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRoundingModulus reads a RoundingModulus from OrderCancelReplaceRequest.
func (m Message) GetRoundingModulus(f *field.RoundingModulusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrdType is a required field for OrderCancelReplaceRequest.
func (m Message) OrdType() (*field.OrdTypeField, quickfix.MessageRejectError) {
	f := &field.OrdTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrdType reads a OrdType from OrderCancelReplaceRequest.
func (m Message) GetOrdType(f *field.OrdTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceType is a non-required field for OrderCancelReplaceRequest.
func (m Message) PriceType() (*field.PriceTypeField, quickfix.MessageRejectError) {
	f := &field.PriceTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceType reads a PriceType from OrderCancelReplaceRequest.
func (m Message) GetPriceType(f *field.PriceTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Price is a non-required field for OrderCancelReplaceRequest.
func (m Message) Price() (*field.PriceField, quickfix.MessageRejectError) {
	f := &field.PriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPrice reads a Price from OrderCancelReplaceRequest.
func (m Message) GetPrice(f *field.PriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StopPx is a non-required field for OrderCancelReplaceRequest.
func (m Message) StopPx() (*field.StopPxField, quickfix.MessageRejectError) {
	f := &field.StopPxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStopPx reads a StopPx from OrderCancelReplaceRequest.
func (m Message) GetStopPx(f *field.StopPxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Spread is a non-required field for OrderCancelReplaceRequest.
func (m Message) Spread() (*field.SpreadField, quickfix.MessageRejectError) {
	f := &field.SpreadField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSpread reads a Spread from OrderCancelReplaceRequest.
func (m Message) GetSpread(f *field.SpreadField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurveCurrency is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkCurveCurrency() (*field.BenchmarkCurveCurrencyField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurveCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurveCurrency reads a BenchmarkCurveCurrency from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkCurveCurrency(f *field.BenchmarkCurveCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurveName is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkCurveName() (*field.BenchmarkCurveNameField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurveNameField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurveName reads a BenchmarkCurveName from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkCurveName(f *field.BenchmarkCurveNameField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurvePoint is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkCurvePoint() (*field.BenchmarkCurvePointField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurvePointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurvePoint reads a BenchmarkCurvePoint from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkCurvePoint(f *field.BenchmarkCurvePointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkPrice is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkPrice() (*field.BenchmarkPriceField, quickfix.MessageRejectError) {
	f := &field.BenchmarkPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkPrice reads a BenchmarkPrice from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkPrice(f *field.BenchmarkPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkPriceType is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkPriceType() (*field.BenchmarkPriceTypeField, quickfix.MessageRejectError) {
	f := &field.BenchmarkPriceTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkPriceType reads a BenchmarkPriceType from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkPriceType(f *field.BenchmarkPriceTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkSecurityID is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkSecurityID() (*field.BenchmarkSecurityIDField, quickfix.MessageRejectError) {
	f := &field.BenchmarkSecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkSecurityID reads a BenchmarkSecurityID from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkSecurityID(f *field.BenchmarkSecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkSecurityIDSource is a non-required field for OrderCancelReplaceRequest.
func (m Message) BenchmarkSecurityIDSource() (*field.BenchmarkSecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.BenchmarkSecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkSecurityIDSource reads a BenchmarkSecurityIDSource from OrderCancelReplaceRequest.
func (m Message) GetBenchmarkSecurityIDSource(f *field.BenchmarkSecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//YieldType is a non-required field for OrderCancelReplaceRequest.
func (m Message) YieldType() (*field.YieldTypeField, quickfix.MessageRejectError) {
	f := &field.YieldTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYieldType reads a YieldType from OrderCancelReplaceRequest.
func (m Message) GetYieldType(f *field.YieldTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Yield is a non-required field for OrderCancelReplaceRequest.
func (m Message) Yield() (*field.YieldField, quickfix.MessageRejectError) {
	f := &field.YieldField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYield reads a Yield from OrderCancelReplaceRequest.
func (m Message) GetYield(f *field.YieldField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//YieldCalcDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) YieldCalcDate() (*field.YieldCalcDateField, quickfix.MessageRejectError) {
	f := &field.YieldCalcDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYieldCalcDate reads a YieldCalcDate from OrderCancelReplaceRequest.
func (m Message) GetYieldCalcDate(f *field.YieldCalcDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//YieldRedemptionDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) YieldRedemptionDate() (*field.YieldRedemptionDateField, quickfix.MessageRejectError) {
	f := &field.YieldRedemptionDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYieldRedemptionDate reads a YieldRedemptionDate from OrderCancelReplaceRequest.
func (m Message) GetYieldRedemptionDate(f *field.YieldRedemptionDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//YieldRedemptionPrice is a non-required field for OrderCancelReplaceRequest.
func (m Message) YieldRedemptionPrice() (*field.YieldRedemptionPriceField, quickfix.MessageRejectError) {
	f := &field.YieldRedemptionPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYieldRedemptionPrice reads a YieldRedemptionPrice from OrderCancelReplaceRequest.
func (m Message) GetYieldRedemptionPrice(f *field.YieldRedemptionPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//YieldRedemptionPriceType is a non-required field for OrderCancelReplaceRequest.
func (m Message) YieldRedemptionPriceType() (*field.YieldRedemptionPriceTypeField, quickfix.MessageRejectError) {
	f := &field.YieldRedemptionPriceTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetYieldRedemptionPriceType reads a YieldRedemptionPriceType from OrderCancelReplaceRequest.
func (m Message) GetYieldRedemptionPriceType(f *field.YieldRedemptionPriceTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegOffsetValue is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegOffsetValue() (*field.PegOffsetValueField, quickfix.MessageRejectError) {
	f := &field.PegOffsetValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegOffsetValue reads a PegOffsetValue from OrderCancelReplaceRequest.
func (m Message) GetPegOffsetValue(f *field.PegOffsetValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegMoveType is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegMoveType() (*field.PegMoveTypeField, quickfix.MessageRejectError) {
	f := &field.PegMoveTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegMoveType reads a PegMoveType from OrderCancelReplaceRequest.
func (m Message) GetPegMoveType(f *field.PegMoveTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegOffsetType is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegOffsetType() (*field.PegOffsetTypeField, quickfix.MessageRejectError) {
	f := &field.PegOffsetTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegOffsetType reads a PegOffsetType from OrderCancelReplaceRequest.
func (m Message) GetPegOffsetType(f *field.PegOffsetTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegLimitType is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegLimitType() (*field.PegLimitTypeField, quickfix.MessageRejectError) {
	f := &field.PegLimitTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegLimitType reads a PegLimitType from OrderCancelReplaceRequest.
func (m Message) GetPegLimitType(f *field.PegLimitTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegRoundDirection is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegRoundDirection() (*field.PegRoundDirectionField, quickfix.MessageRejectError) {
	f := &field.PegRoundDirectionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegRoundDirection reads a PegRoundDirection from OrderCancelReplaceRequest.
func (m Message) GetPegRoundDirection(f *field.PegRoundDirectionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PegScope is a non-required field for OrderCancelReplaceRequest.
func (m Message) PegScope() (*field.PegScopeField, quickfix.MessageRejectError) {
	f := &field.PegScopeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPegScope reads a PegScope from OrderCancelReplaceRequest.
func (m Message) GetPegScope(f *field.PegScopeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionInst is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionInst() (*field.DiscretionInstField, quickfix.MessageRejectError) {
	f := &field.DiscretionInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionInst reads a DiscretionInst from OrderCancelReplaceRequest.
func (m Message) GetDiscretionInst(f *field.DiscretionInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionOffsetValue is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionOffsetValue() (*field.DiscretionOffsetValueField, quickfix.MessageRejectError) {
	f := &field.DiscretionOffsetValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionOffsetValue reads a DiscretionOffsetValue from OrderCancelReplaceRequest.
func (m Message) GetDiscretionOffsetValue(f *field.DiscretionOffsetValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionMoveType is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionMoveType() (*field.DiscretionMoveTypeField, quickfix.MessageRejectError) {
	f := &field.DiscretionMoveTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionMoveType reads a DiscretionMoveType from OrderCancelReplaceRequest.
func (m Message) GetDiscretionMoveType(f *field.DiscretionMoveTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionOffsetType is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionOffsetType() (*field.DiscretionOffsetTypeField, quickfix.MessageRejectError) {
	f := &field.DiscretionOffsetTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionOffsetType reads a DiscretionOffsetType from OrderCancelReplaceRequest.
func (m Message) GetDiscretionOffsetType(f *field.DiscretionOffsetTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionLimitType is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionLimitType() (*field.DiscretionLimitTypeField, quickfix.MessageRejectError) {
	f := &field.DiscretionLimitTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionLimitType reads a DiscretionLimitType from OrderCancelReplaceRequest.
func (m Message) GetDiscretionLimitType(f *field.DiscretionLimitTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionRoundDirection is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionRoundDirection() (*field.DiscretionRoundDirectionField, quickfix.MessageRejectError) {
	f := &field.DiscretionRoundDirectionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionRoundDirection reads a DiscretionRoundDirection from OrderCancelReplaceRequest.
func (m Message) GetDiscretionRoundDirection(f *field.DiscretionRoundDirectionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DiscretionScope is a non-required field for OrderCancelReplaceRequest.
func (m Message) DiscretionScope() (*field.DiscretionScopeField, quickfix.MessageRejectError) {
	f := &field.DiscretionScopeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDiscretionScope reads a DiscretionScope from OrderCancelReplaceRequest.
func (m Message) GetDiscretionScope(f *field.DiscretionScopeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TargetStrategy is a non-required field for OrderCancelReplaceRequest.
func (m Message) TargetStrategy() (*field.TargetStrategyField, quickfix.MessageRejectError) {
	f := &field.TargetStrategyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTargetStrategy reads a TargetStrategy from OrderCancelReplaceRequest.
func (m Message) GetTargetStrategy(f *field.TargetStrategyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TargetStrategyParameters is a non-required field for OrderCancelReplaceRequest.
func (m Message) TargetStrategyParameters() (*field.TargetStrategyParametersField, quickfix.MessageRejectError) {
	f := &field.TargetStrategyParametersField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTargetStrategyParameters reads a TargetStrategyParameters from OrderCancelReplaceRequest.
func (m Message) GetTargetStrategyParameters(f *field.TargetStrategyParametersField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ParticipationRate is a non-required field for OrderCancelReplaceRequest.
func (m Message) ParticipationRate() (*field.ParticipationRateField, quickfix.MessageRejectError) {
	f := &field.ParticipationRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetParticipationRate reads a ParticipationRate from OrderCancelReplaceRequest.
func (m Message) GetParticipationRate(f *field.ParticipationRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ComplianceID is a non-required field for OrderCancelReplaceRequest.
func (m Message) ComplianceID() (*field.ComplianceIDField, quickfix.MessageRejectError) {
	f := &field.ComplianceIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetComplianceID reads a ComplianceID from OrderCancelReplaceRequest.
func (m Message) GetComplianceID(f *field.ComplianceIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SolicitedFlag is a non-required field for OrderCancelReplaceRequest.
func (m Message) SolicitedFlag() (*field.SolicitedFlagField, quickfix.MessageRejectError) {
	f := &field.SolicitedFlagField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSolicitedFlag reads a SolicitedFlag from OrderCancelReplaceRequest.
func (m Message) GetSolicitedFlag(f *field.SolicitedFlagField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Currency is a non-required field for OrderCancelReplaceRequest.
func (m Message) Currency() (*field.CurrencyField, quickfix.MessageRejectError) {
	f := &field.CurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCurrency reads a Currency from OrderCancelReplaceRequest.
func (m Message) GetCurrency(f *field.CurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TimeInForce is a non-required field for OrderCancelReplaceRequest.
func (m Message) TimeInForce() (*field.TimeInForceField, quickfix.MessageRejectError) {
	f := &field.TimeInForceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTimeInForce reads a TimeInForce from OrderCancelReplaceRequest.
func (m Message) GetTimeInForce(f *field.TimeInForceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EffectiveTime is a non-required field for OrderCancelReplaceRequest.
func (m Message) EffectiveTime() (*field.EffectiveTimeField, quickfix.MessageRejectError) {
	f := &field.EffectiveTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEffectiveTime reads a EffectiveTime from OrderCancelReplaceRequest.
func (m Message) GetEffectiveTime(f *field.EffectiveTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExpireDate is a non-required field for OrderCancelReplaceRequest.
func (m Message) ExpireDate() (*field.ExpireDateField, quickfix.MessageRejectError) {
	f := &field.ExpireDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExpireDate reads a ExpireDate from OrderCancelReplaceRequest.
func (m Message) GetExpireDate(f *field.ExpireDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExpireTime is a non-required field for OrderCancelReplaceRequest.
func (m Message) ExpireTime() (*field.ExpireTimeField, quickfix.MessageRejectError) {
	f := &field.ExpireTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExpireTime reads a ExpireTime from OrderCancelReplaceRequest.
func (m Message) GetExpireTime(f *field.ExpireTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//GTBookingInst is a non-required field for OrderCancelReplaceRequest.
func (m Message) GTBookingInst() (*field.GTBookingInstField, quickfix.MessageRejectError) {
	f := &field.GTBookingInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetGTBookingInst reads a GTBookingInst from OrderCancelReplaceRequest.
func (m Message) GetGTBookingInst(f *field.GTBookingInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Commission is a non-required field for OrderCancelReplaceRequest.
func (m Message) Commission() (*field.CommissionField, quickfix.MessageRejectError) {
	f := &field.CommissionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCommission reads a Commission from OrderCancelReplaceRequest.
func (m Message) GetCommission(f *field.CommissionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CommType is a non-required field for OrderCancelReplaceRequest.
func (m Message) CommType() (*field.CommTypeField, quickfix.MessageRejectError) {
	f := &field.CommTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCommType reads a CommType from OrderCancelReplaceRequest.
func (m Message) GetCommType(f *field.CommTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CommCurrency is a non-required field for OrderCancelReplaceRequest.
func (m Message) CommCurrency() (*field.CommCurrencyField, quickfix.MessageRejectError) {
	f := &field.CommCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCommCurrency reads a CommCurrency from OrderCancelReplaceRequest.
func (m Message) GetCommCurrency(f *field.CommCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FundRenewWaiv is a non-required field for OrderCancelReplaceRequest.
func (m Message) FundRenewWaiv() (*field.FundRenewWaivField, quickfix.MessageRejectError) {
	f := &field.FundRenewWaivField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFundRenewWaiv reads a FundRenewWaiv from OrderCancelReplaceRequest.
func (m Message) GetFundRenewWaiv(f *field.FundRenewWaivField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderCapacity is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderCapacity() (*field.OrderCapacityField, quickfix.MessageRejectError) {
	f := &field.OrderCapacityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderCapacity reads a OrderCapacity from OrderCancelReplaceRequest.
func (m Message) GetOrderCapacity(f *field.OrderCapacityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderRestrictions is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderRestrictions() (*field.OrderRestrictionsField, quickfix.MessageRejectError) {
	f := &field.OrderRestrictionsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderRestrictions reads a OrderRestrictions from OrderCancelReplaceRequest.
func (m Message) GetOrderRestrictions(f *field.OrderRestrictionsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CustOrderCapacity is a non-required field for OrderCancelReplaceRequest.
func (m Message) CustOrderCapacity() (*field.CustOrderCapacityField, quickfix.MessageRejectError) {
	f := &field.CustOrderCapacityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCustOrderCapacity reads a CustOrderCapacity from OrderCancelReplaceRequest.
func (m Message) GetCustOrderCapacity(f *field.CustOrderCapacityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ForexReq is a non-required field for OrderCancelReplaceRequest.
func (m Message) ForexReq() (*field.ForexReqField, quickfix.MessageRejectError) {
	f := &field.ForexReqField{}
	err := m.Body.Get(f)
	return f, err
}

//GetForexReq reads a ForexReq from OrderCancelReplaceRequest.
func (m Message) GetForexReq(f *field.ForexReqField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlCurrency is a non-required field for OrderCancelReplaceRequest.
func (m Message) SettlCurrency() (*field.SettlCurrencyField, quickfix.MessageRejectError) {
	f := &field.SettlCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlCurrency reads a SettlCurrency from OrderCancelReplaceRequest.
func (m Message) GetSettlCurrency(f *field.SettlCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BookingType is a non-required field for OrderCancelReplaceRequest.
func (m Message) BookingType() (*field.BookingTypeField, quickfix.MessageRejectError) {
	f := &field.BookingTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBookingType reads a BookingType from OrderCancelReplaceRequest.
func (m Message) GetBookingType(f *field.BookingTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for OrderCancelReplaceRequest.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from OrderCancelReplaceRequest.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedTextLen is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedTextLen() (*field.EncodedTextLenField, quickfix.MessageRejectError) {
	f := &field.EncodedTextLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedTextLen reads a EncodedTextLen from OrderCancelReplaceRequest.
func (m Message) GetEncodedTextLen(f *field.EncodedTextLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedText is a non-required field for OrderCancelReplaceRequest.
func (m Message) EncodedText() (*field.EncodedTextField, quickfix.MessageRejectError) {
	f := &field.EncodedTextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedText reads a EncodedText from OrderCancelReplaceRequest.
func (m Message) GetEncodedText(f *field.EncodedTextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlDate2 is a non-required field for OrderCancelReplaceRequest.
func (m Message) SettlDate2() (*field.SettlDate2Field, quickfix.MessageRejectError) {
	f := &field.SettlDate2Field{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlDate2 reads a SettlDate2 from OrderCancelReplaceRequest.
func (m Message) GetSettlDate2(f *field.SettlDate2Field) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderQty2 is a non-required field for OrderCancelReplaceRequest.
func (m Message) OrderQty2() (*field.OrderQty2Field, quickfix.MessageRejectError) {
	f := &field.OrderQty2Field{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderQty2 reads a OrderQty2 from OrderCancelReplaceRequest.
func (m Message) GetOrderQty2(f *field.OrderQty2Field) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Price2 is a non-required field for OrderCancelReplaceRequest.
func (m Message) Price2() (*field.Price2Field, quickfix.MessageRejectError) {
	f := &field.Price2Field{}
	err := m.Body.Get(f)
	return f, err
}

//GetPrice2 reads a Price2 from OrderCancelReplaceRequest.
func (m Message) GetPrice2(f *field.Price2Field) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PositionEffect is a non-required field for OrderCancelReplaceRequest.
func (m Message) PositionEffect() (*field.PositionEffectField, quickfix.MessageRejectError) {
	f := &field.PositionEffectField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPositionEffect reads a PositionEffect from OrderCancelReplaceRequest.
func (m Message) GetPositionEffect(f *field.PositionEffectField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CoveredOrUncovered is a non-required field for OrderCancelReplaceRequest.
func (m Message) CoveredOrUncovered() (*field.CoveredOrUncoveredField, quickfix.MessageRejectError) {
	f := &field.CoveredOrUncoveredField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCoveredOrUncovered reads a CoveredOrUncovered from OrderCancelReplaceRequest.
func (m Message) GetCoveredOrUncovered(f *field.CoveredOrUncoveredField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaxShow is a non-required field for OrderCancelReplaceRequest.
func (m Message) MaxShow() (*field.MaxShowField, quickfix.MessageRejectError) {
	f := &field.MaxShowField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaxShow reads a MaxShow from OrderCancelReplaceRequest.
func (m Message) GetMaxShow(f *field.MaxShowField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//LocateReqd is a non-required field for OrderCancelReplaceRequest.
func (m Message) LocateReqd() (*field.LocateReqdField, quickfix.MessageRejectError) {
	f := &field.LocateReqdField{}
	err := m.Body.Get(f)
	return f, err
}

//GetLocateReqd reads a LocateReqd from OrderCancelReplaceRequest.
func (m Message) GetLocateReqd(f *field.LocateReqdField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CancellationRights is a non-required field for OrderCancelReplaceRequest.
func (m Message) CancellationRights() (*field.CancellationRightsField, quickfix.MessageRejectError) {
	f := &field.CancellationRightsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCancellationRights reads a CancellationRights from OrderCancelReplaceRequest.
func (m Message) GetCancellationRights(f *field.CancellationRightsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MoneyLaunderingStatus is a non-required field for OrderCancelReplaceRequest.
func (m Message) MoneyLaunderingStatus() (*field.MoneyLaunderingStatusField, quickfix.MessageRejectError) {
	f := &field.MoneyLaunderingStatusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMoneyLaunderingStatus reads a MoneyLaunderingStatus from OrderCancelReplaceRequest.
func (m Message) GetMoneyLaunderingStatus(f *field.MoneyLaunderingStatusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RegistID is a non-required field for OrderCancelReplaceRequest.
func (m Message) RegistID() (*field.RegistIDField, quickfix.MessageRejectError) {
	f := &field.RegistIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRegistID reads a RegistID from OrderCancelReplaceRequest.
func (m Message) GetRegistID(f *field.RegistIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Designation is a non-required field for OrderCancelReplaceRequest.
func (m Message) Designation() (*field.DesignationField, quickfix.MessageRejectError) {
	f := &field.DesignationField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDesignation reads a Designation from OrderCancelReplaceRequest.
func (m Message) GetDesignation(f *field.DesignationField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for OrderCancelReplaceRequest.
func New(
	origclordid *field.OrigClOrdIDField,
	clordid *field.ClOrdIDField,
	side *field.SideField,
	transacttime *field.TransactTimeField,
	ordtype *field.OrdTypeField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(enum.BeginStringFIX44))
	builder.Header.Set(field.NewMsgType("G"))
	builder.Body.Set(origclordid)
	builder.Body.Set(clordid)
	builder.Body.Set(side)
	builder.Body.Set(transacttime)
	builder.Body.Set(ordtype)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.BeginStringFIX44, "G", r
}
