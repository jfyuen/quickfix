//Package collateralinquiry msg type = BB.
package collateralinquiry

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

import (
	"github.com/quickfixgo/quickfix/fix/enum"
)

//Message is a CollateralInquiry wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//CollInquiryID is a required field for CollateralInquiry.
func (m Message) CollInquiryID() (*field.CollInquiryIDField, quickfix.MessageRejectError) {
	f := &field.CollInquiryIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCollInquiryID reads a CollInquiryID from CollateralInquiry.
func (m Message) GetCollInquiryID(f *field.CollInquiryIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoCollInquiryQualifier is a non-required field for CollateralInquiry.
func (m Message) NoCollInquiryQualifier() (*field.NoCollInquiryQualifierField, quickfix.MessageRejectError) {
	f := &field.NoCollInquiryQualifierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoCollInquiryQualifier reads a NoCollInquiryQualifier from CollateralInquiry.
func (m Message) GetNoCollInquiryQualifier(f *field.NoCollInquiryQualifierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SubscriptionRequestType is a non-required field for CollateralInquiry.
func (m Message) SubscriptionRequestType() (*field.SubscriptionRequestTypeField, quickfix.MessageRejectError) {
	f := &field.SubscriptionRequestTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSubscriptionRequestType reads a SubscriptionRequestType from CollateralInquiry.
func (m Message) GetSubscriptionRequestType(f *field.SubscriptionRequestTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ResponseTransportType is a non-required field for CollateralInquiry.
func (m Message) ResponseTransportType() (*field.ResponseTransportTypeField, quickfix.MessageRejectError) {
	f := &field.ResponseTransportTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetResponseTransportType reads a ResponseTransportType from CollateralInquiry.
func (m Message) GetResponseTransportType(f *field.ResponseTransportTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ResponseDestination is a non-required field for CollateralInquiry.
func (m Message) ResponseDestination() (*field.ResponseDestinationField, quickfix.MessageRejectError) {
	f := &field.ResponseDestinationField{}
	err := m.Body.Get(f)
	return f, err
}

//GetResponseDestination reads a ResponseDestination from CollateralInquiry.
func (m Message) GetResponseDestination(f *field.ResponseDestinationField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPartyIDs is a non-required field for CollateralInquiry.
func (m Message) NoPartyIDs() (*field.NoPartyIDsField, quickfix.MessageRejectError) {
	f := &field.NoPartyIDsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPartyIDs reads a NoPartyIDs from CollateralInquiry.
func (m Message) GetNoPartyIDs(f *field.NoPartyIDsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Account is a non-required field for CollateralInquiry.
func (m Message) Account() (*field.AccountField, quickfix.MessageRejectError) {
	f := &field.AccountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccount reads a Account from CollateralInquiry.
func (m Message) GetAccount(f *field.AccountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AccountType is a non-required field for CollateralInquiry.
func (m Message) AccountType() (*field.AccountTypeField, quickfix.MessageRejectError) {
	f := &field.AccountTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccountType reads a AccountType from CollateralInquiry.
func (m Message) GetAccountType(f *field.AccountTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClOrdID is a non-required field for CollateralInquiry.
func (m Message) ClOrdID() (*field.ClOrdIDField, quickfix.MessageRejectError) {
	f := &field.ClOrdIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClOrdID reads a ClOrdID from CollateralInquiry.
func (m Message) GetClOrdID(f *field.ClOrdIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrderID is a non-required field for CollateralInquiry.
func (m Message) OrderID() (*field.OrderIDField, quickfix.MessageRejectError) {
	f := &field.OrderIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrderID reads a OrderID from CollateralInquiry.
func (m Message) GetOrderID(f *field.OrderIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecondaryOrderID is a non-required field for CollateralInquiry.
func (m Message) SecondaryOrderID() (*field.SecondaryOrderIDField, quickfix.MessageRejectError) {
	f := &field.SecondaryOrderIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecondaryOrderID reads a SecondaryOrderID from CollateralInquiry.
func (m Message) GetSecondaryOrderID(f *field.SecondaryOrderIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecondaryClOrdID is a non-required field for CollateralInquiry.
func (m Message) SecondaryClOrdID() (*field.SecondaryClOrdIDField, quickfix.MessageRejectError) {
	f := &field.SecondaryClOrdIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecondaryClOrdID reads a SecondaryClOrdID from CollateralInquiry.
func (m Message) GetSecondaryClOrdID(f *field.SecondaryClOrdIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoExecs is a non-required field for CollateralInquiry.
func (m Message) NoExecs() (*field.NoExecsField, quickfix.MessageRejectError) {
	f := &field.NoExecsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoExecs reads a NoExecs from CollateralInquiry.
func (m Message) GetNoExecs(f *field.NoExecsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoTrades is a non-required field for CollateralInquiry.
func (m Message) NoTrades() (*field.NoTradesField, quickfix.MessageRejectError) {
	f := &field.NoTradesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoTrades reads a NoTrades from CollateralInquiry.
func (m Message) GetNoTrades(f *field.NoTradesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Symbol is a non-required field for CollateralInquiry.
func (m Message) Symbol() (*field.SymbolField, quickfix.MessageRejectError) {
	f := &field.SymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbol reads a Symbol from CollateralInquiry.
func (m Message) GetSymbol(f *field.SymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SymbolSfx is a non-required field for CollateralInquiry.
func (m Message) SymbolSfx() (*field.SymbolSfxField, quickfix.MessageRejectError) {
	f := &field.SymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbolSfx reads a SymbolSfx from CollateralInquiry.
func (m Message) GetSymbolSfx(f *field.SymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityID is a non-required field for CollateralInquiry.
func (m Message) SecurityID() (*field.SecurityIDField, quickfix.MessageRejectError) {
	f := &field.SecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityID reads a SecurityID from CollateralInquiry.
func (m Message) GetSecurityID(f *field.SecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityIDSource is a non-required field for CollateralInquiry.
func (m Message) SecurityIDSource() (*field.SecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.SecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityIDSource reads a SecurityIDSource from CollateralInquiry.
func (m Message) GetSecurityIDSource(f *field.SecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoSecurityAltID is a non-required field for CollateralInquiry.
func (m Message) NoSecurityAltID() (*field.NoSecurityAltIDField, quickfix.MessageRejectError) {
	f := &field.NoSecurityAltIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoSecurityAltID reads a NoSecurityAltID from CollateralInquiry.
func (m Message) GetNoSecurityAltID(f *field.NoSecurityAltIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Product is a non-required field for CollateralInquiry.
func (m Message) Product() (*field.ProductField, quickfix.MessageRejectError) {
	f := &field.ProductField{}
	err := m.Body.Get(f)
	return f, err
}

//GetProduct reads a Product from CollateralInquiry.
func (m Message) GetProduct(f *field.ProductField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CFICode is a non-required field for CollateralInquiry.
func (m Message) CFICode() (*field.CFICodeField, quickfix.MessageRejectError) {
	f := &field.CFICodeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCFICode reads a CFICode from CollateralInquiry.
func (m Message) GetCFICode(f *field.CFICodeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityType is a non-required field for CollateralInquiry.
func (m Message) SecurityType() (*field.SecurityTypeField, quickfix.MessageRejectError) {
	f := &field.SecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityType reads a SecurityType from CollateralInquiry.
func (m Message) GetSecurityType(f *field.SecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecuritySubType is a non-required field for CollateralInquiry.
func (m Message) SecuritySubType() (*field.SecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.SecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecuritySubType reads a SecuritySubType from CollateralInquiry.
func (m Message) GetSecuritySubType(f *field.SecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityMonthYear is a non-required field for CollateralInquiry.
func (m Message) MaturityMonthYear() (*field.MaturityMonthYearField, quickfix.MessageRejectError) {
	f := &field.MaturityMonthYearField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityMonthYear reads a MaturityMonthYear from CollateralInquiry.
func (m Message) GetMaturityMonthYear(f *field.MaturityMonthYearField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityDate is a non-required field for CollateralInquiry.
func (m Message) MaturityDate() (*field.MaturityDateField, quickfix.MessageRejectError) {
	f := &field.MaturityDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityDate reads a MaturityDate from CollateralInquiry.
func (m Message) GetMaturityDate(f *field.MaturityDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponPaymentDate is a non-required field for CollateralInquiry.
func (m Message) CouponPaymentDate() (*field.CouponPaymentDateField, quickfix.MessageRejectError) {
	f := &field.CouponPaymentDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponPaymentDate reads a CouponPaymentDate from CollateralInquiry.
func (m Message) GetCouponPaymentDate(f *field.CouponPaymentDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//IssueDate is a non-required field for CollateralInquiry.
func (m Message) IssueDate() (*field.IssueDateField, quickfix.MessageRejectError) {
	f := &field.IssueDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssueDate reads a IssueDate from CollateralInquiry.
func (m Message) GetIssueDate(f *field.IssueDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepoCollateralSecurityType is a non-required field for CollateralInquiry.
func (m Message) RepoCollateralSecurityType() (*field.RepoCollateralSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.RepoCollateralSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepoCollateralSecurityType reads a RepoCollateralSecurityType from CollateralInquiry.
func (m Message) GetRepoCollateralSecurityType(f *field.RepoCollateralSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseTerm is a non-required field for CollateralInquiry.
func (m Message) RepurchaseTerm() (*field.RepurchaseTermField, quickfix.MessageRejectError) {
	f := &field.RepurchaseTermField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseTerm reads a RepurchaseTerm from CollateralInquiry.
func (m Message) GetRepurchaseTerm(f *field.RepurchaseTermField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseRate is a non-required field for CollateralInquiry.
func (m Message) RepurchaseRate() (*field.RepurchaseRateField, quickfix.MessageRejectError) {
	f := &field.RepurchaseRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseRate reads a RepurchaseRate from CollateralInquiry.
func (m Message) GetRepurchaseRate(f *field.RepurchaseRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Factor is a non-required field for CollateralInquiry.
func (m Message) Factor() (*field.FactorField, quickfix.MessageRejectError) {
	f := &field.FactorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFactor reads a Factor from CollateralInquiry.
func (m Message) GetFactor(f *field.FactorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CreditRating is a non-required field for CollateralInquiry.
func (m Message) CreditRating() (*field.CreditRatingField, quickfix.MessageRejectError) {
	f := &field.CreditRatingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCreditRating reads a CreditRating from CollateralInquiry.
func (m Message) GetCreditRating(f *field.CreditRatingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InstrRegistry is a non-required field for CollateralInquiry.
func (m Message) InstrRegistry() (*field.InstrRegistryField, quickfix.MessageRejectError) {
	f := &field.InstrRegistryField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInstrRegistry reads a InstrRegistry from CollateralInquiry.
func (m Message) GetInstrRegistry(f *field.InstrRegistryField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CountryOfIssue is a non-required field for CollateralInquiry.
func (m Message) CountryOfIssue() (*field.CountryOfIssueField, quickfix.MessageRejectError) {
	f := &field.CountryOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCountryOfIssue reads a CountryOfIssue from CollateralInquiry.
func (m Message) GetCountryOfIssue(f *field.CountryOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StateOrProvinceOfIssue is a non-required field for CollateralInquiry.
func (m Message) StateOrProvinceOfIssue() (*field.StateOrProvinceOfIssueField, quickfix.MessageRejectError) {
	f := &field.StateOrProvinceOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStateOrProvinceOfIssue reads a StateOrProvinceOfIssue from CollateralInquiry.
func (m Message) GetStateOrProvinceOfIssue(f *field.StateOrProvinceOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//LocaleOfIssue is a non-required field for CollateralInquiry.
func (m Message) LocaleOfIssue() (*field.LocaleOfIssueField, quickfix.MessageRejectError) {
	f := &field.LocaleOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetLocaleOfIssue reads a LocaleOfIssue from CollateralInquiry.
func (m Message) GetLocaleOfIssue(f *field.LocaleOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RedemptionDate is a non-required field for CollateralInquiry.
func (m Message) RedemptionDate() (*field.RedemptionDateField, quickfix.MessageRejectError) {
	f := &field.RedemptionDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRedemptionDate reads a RedemptionDate from CollateralInquiry.
func (m Message) GetRedemptionDate(f *field.RedemptionDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePrice is a non-required field for CollateralInquiry.
func (m Message) StrikePrice() (*field.StrikePriceField, quickfix.MessageRejectError) {
	f := &field.StrikePriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePrice reads a StrikePrice from CollateralInquiry.
func (m Message) GetStrikePrice(f *field.StrikePriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeCurrency is a non-required field for CollateralInquiry.
func (m Message) StrikeCurrency() (*field.StrikeCurrencyField, quickfix.MessageRejectError) {
	f := &field.StrikeCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeCurrency reads a StrikeCurrency from CollateralInquiry.
func (m Message) GetStrikeCurrency(f *field.StrikeCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptAttribute is a non-required field for CollateralInquiry.
func (m Message) OptAttribute() (*field.OptAttributeField, quickfix.MessageRejectError) {
	f := &field.OptAttributeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptAttribute reads a OptAttribute from CollateralInquiry.
func (m Message) GetOptAttribute(f *field.OptAttributeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractMultiplier is a non-required field for CollateralInquiry.
func (m Message) ContractMultiplier() (*field.ContractMultiplierField, quickfix.MessageRejectError) {
	f := &field.ContractMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractMultiplier reads a ContractMultiplier from CollateralInquiry.
func (m Message) GetContractMultiplier(f *field.ContractMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponRate is a non-required field for CollateralInquiry.
func (m Message) CouponRate() (*field.CouponRateField, quickfix.MessageRejectError) {
	f := &field.CouponRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponRate reads a CouponRate from CollateralInquiry.
func (m Message) GetCouponRate(f *field.CouponRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityExchange is a non-required field for CollateralInquiry.
func (m Message) SecurityExchange() (*field.SecurityExchangeField, quickfix.MessageRejectError) {
	f := &field.SecurityExchangeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityExchange reads a SecurityExchange from CollateralInquiry.
func (m Message) GetSecurityExchange(f *field.SecurityExchangeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Issuer is a non-required field for CollateralInquiry.
func (m Message) Issuer() (*field.IssuerField, quickfix.MessageRejectError) {
	f := &field.IssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssuer reads a Issuer from CollateralInquiry.
func (m Message) GetIssuer(f *field.IssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuerLen is a non-required field for CollateralInquiry.
func (m Message) EncodedIssuerLen() (*field.EncodedIssuerLenField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuerLen reads a EncodedIssuerLen from CollateralInquiry.
func (m Message) GetEncodedIssuerLen(f *field.EncodedIssuerLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuer is a non-required field for CollateralInquiry.
func (m Message) EncodedIssuer() (*field.EncodedIssuerField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuer reads a EncodedIssuer from CollateralInquiry.
func (m Message) GetEncodedIssuer(f *field.EncodedIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityDesc is a non-required field for CollateralInquiry.
func (m Message) SecurityDesc() (*field.SecurityDescField, quickfix.MessageRejectError) {
	f := &field.SecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityDesc reads a SecurityDesc from CollateralInquiry.
func (m Message) GetSecurityDesc(f *field.SecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDescLen is a non-required field for CollateralInquiry.
func (m Message) EncodedSecurityDescLen() (*field.EncodedSecurityDescLenField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDescLen reads a EncodedSecurityDescLen from CollateralInquiry.
func (m Message) GetEncodedSecurityDescLen(f *field.EncodedSecurityDescLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDesc is a non-required field for CollateralInquiry.
func (m Message) EncodedSecurityDesc() (*field.EncodedSecurityDescField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDesc reads a EncodedSecurityDesc from CollateralInquiry.
func (m Message) GetEncodedSecurityDesc(f *field.EncodedSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Pool is a non-required field for CollateralInquiry.
func (m Message) Pool() (*field.PoolField, quickfix.MessageRejectError) {
	f := &field.PoolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPool reads a Pool from CollateralInquiry.
func (m Message) GetPool(f *field.PoolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractSettlMonth is a non-required field for CollateralInquiry.
func (m Message) ContractSettlMonth() (*field.ContractSettlMonthField, quickfix.MessageRejectError) {
	f := &field.ContractSettlMonthField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractSettlMonth reads a ContractSettlMonth from CollateralInquiry.
func (m Message) GetContractSettlMonth(f *field.ContractSettlMonthField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPProgram is a non-required field for CollateralInquiry.
func (m Message) CPProgram() (*field.CPProgramField, quickfix.MessageRejectError) {
	f := &field.CPProgramField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPProgram reads a CPProgram from CollateralInquiry.
func (m Message) GetCPProgram(f *field.CPProgramField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPRegType is a non-required field for CollateralInquiry.
func (m Message) CPRegType() (*field.CPRegTypeField, quickfix.MessageRejectError) {
	f := &field.CPRegTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPRegType reads a CPRegType from CollateralInquiry.
func (m Message) GetCPRegType(f *field.CPRegTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoEvents is a non-required field for CollateralInquiry.
func (m Message) NoEvents() (*field.NoEventsField, quickfix.MessageRejectError) {
	f := &field.NoEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoEvents reads a NoEvents from CollateralInquiry.
func (m Message) GetNoEvents(f *field.NoEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DatedDate is a non-required field for CollateralInquiry.
func (m Message) DatedDate() (*field.DatedDateField, quickfix.MessageRejectError) {
	f := &field.DatedDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDatedDate reads a DatedDate from CollateralInquiry.
func (m Message) GetDatedDate(f *field.DatedDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InterestAccrualDate is a non-required field for CollateralInquiry.
func (m Message) InterestAccrualDate() (*field.InterestAccrualDateField, quickfix.MessageRejectError) {
	f := &field.InterestAccrualDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInterestAccrualDate reads a InterestAccrualDate from CollateralInquiry.
func (m Message) GetInterestAccrualDate(f *field.InterestAccrualDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityStatus is a non-required field for CollateralInquiry.
func (m Message) SecurityStatus() (*field.SecurityStatusField, quickfix.MessageRejectError) {
	f := &field.SecurityStatusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityStatus reads a SecurityStatus from CollateralInquiry.
func (m Message) GetSecurityStatus(f *field.SecurityStatusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettleOnOpenFlag is a non-required field for CollateralInquiry.
func (m Message) SettleOnOpenFlag() (*field.SettleOnOpenFlagField, quickfix.MessageRejectError) {
	f := &field.SettleOnOpenFlagField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettleOnOpenFlag reads a SettleOnOpenFlag from CollateralInquiry.
func (m Message) GetSettleOnOpenFlag(f *field.SettleOnOpenFlagField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InstrmtAssignmentMethod is a non-required field for CollateralInquiry.
func (m Message) InstrmtAssignmentMethod() (*field.InstrmtAssignmentMethodField, quickfix.MessageRejectError) {
	f := &field.InstrmtAssignmentMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInstrmtAssignmentMethod reads a InstrmtAssignmentMethod from CollateralInquiry.
func (m Message) GetInstrmtAssignmentMethod(f *field.InstrmtAssignmentMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeMultiplier is a non-required field for CollateralInquiry.
func (m Message) StrikeMultiplier() (*field.StrikeMultiplierField, quickfix.MessageRejectError) {
	f := &field.StrikeMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeMultiplier reads a StrikeMultiplier from CollateralInquiry.
func (m Message) GetStrikeMultiplier(f *field.StrikeMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeValue is a non-required field for CollateralInquiry.
func (m Message) StrikeValue() (*field.StrikeValueField, quickfix.MessageRejectError) {
	f := &field.StrikeValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeValue reads a StrikeValue from CollateralInquiry.
func (m Message) GetStrikeValue(f *field.StrikeValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MinPriceIncrement is a non-required field for CollateralInquiry.
func (m Message) MinPriceIncrement() (*field.MinPriceIncrementField, quickfix.MessageRejectError) {
	f := &field.MinPriceIncrementField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMinPriceIncrement reads a MinPriceIncrement from CollateralInquiry.
func (m Message) GetMinPriceIncrement(f *field.MinPriceIncrementField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PositionLimit is a non-required field for CollateralInquiry.
func (m Message) PositionLimit() (*field.PositionLimitField, quickfix.MessageRejectError) {
	f := &field.PositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPositionLimit reads a PositionLimit from CollateralInquiry.
func (m Message) GetPositionLimit(f *field.PositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NTPositionLimit is a non-required field for CollateralInquiry.
func (m Message) NTPositionLimit() (*field.NTPositionLimitField, quickfix.MessageRejectError) {
	f := &field.NTPositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNTPositionLimit reads a NTPositionLimit from CollateralInquiry.
func (m Message) GetNTPositionLimit(f *field.NTPositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoInstrumentParties is a non-required field for CollateralInquiry.
func (m Message) NoInstrumentParties() (*field.NoInstrumentPartiesField, quickfix.MessageRejectError) {
	f := &field.NoInstrumentPartiesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoInstrumentParties reads a NoInstrumentParties from CollateralInquiry.
func (m Message) GetNoInstrumentParties(f *field.NoInstrumentPartiesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnitOfMeasure is a non-required field for CollateralInquiry.
func (m Message) UnitOfMeasure() (*field.UnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.UnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnitOfMeasure reads a UnitOfMeasure from CollateralInquiry.
func (m Message) GetUnitOfMeasure(f *field.UnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TimeUnit is a non-required field for CollateralInquiry.
func (m Message) TimeUnit() (*field.TimeUnitField, quickfix.MessageRejectError) {
	f := &field.TimeUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTimeUnit reads a TimeUnit from CollateralInquiry.
func (m Message) GetTimeUnit(f *field.TimeUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityTime is a non-required field for CollateralInquiry.
func (m Message) MaturityTime() (*field.MaturityTimeField, quickfix.MessageRejectError) {
	f := &field.MaturityTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityTime reads a MaturityTime from CollateralInquiry.
func (m Message) GetMaturityTime(f *field.MaturityTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityGroup is a non-required field for CollateralInquiry.
func (m Message) SecurityGroup() (*field.SecurityGroupField, quickfix.MessageRejectError) {
	f := &field.SecurityGroupField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityGroup reads a SecurityGroup from CollateralInquiry.
func (m Message) GetSecurityGroup(f *field.SecurityGroupField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MinPriceIncrementAmount is a non-required field for CollateralInquiry.
func (m Message) MinPriceIncrementAmount() (*field.MinPriceIncrementAmountField, quickfix.MessageRejectError) {
	f := &field.MinPriceIncrementAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMinPriceIncrementAmount reads a MinPriceIncrementAmount from CollateralInquiry.
func (m Message) GetMinPriceIncrementAmount(f *field.MinPriceIncrementAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnitOfMeasureQty is a non-required field for CollateralInquiry.
func (m Message) UnitOfMeasureQty() (*field.UnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.UnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnitOfMeasureQty reads a UnitOfMeasureQty from CollateralInquiry.
func (m Message) GetUnitOfMeasureQty(f *field.UnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXMLLen is a non-required field for CollateralInquiry.
func (m Message) SecurityXMLLen() (*field.SecurityXMLLenField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXMLLen reads a SecurityXMLLen from CollateralInquiry.
func (m Message) GetSecurityXMLLen(f *field.SecurityXMLLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXML is a non-required field for CollateralInquiry.
func (m Message) SecurityXML() (*field.SecurityXMLField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXML reads a SecurityXML from CollateralInquiry.
func (m Message) GetSecurityXML(f *field.SecurityXMLField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXMLSchema is a non-required field for CollateralInquiry.
func (m Message) SecurityXMLSchema() (*field.SecurityXMLSchemaField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLSchemaField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXMLSchema reads a SecurityXMLSchema from CollateralInquiry.
func (m Message) GetSecurityXMLSchema(f *field.SecurityXMLSchemaField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ProductComplex is a non-required field for CollateralInquiry.
func (m Message) ProductComplex() (*field.ProductComplexField, quickfix.MessageRejectError) {
	f := &field.ProductComplexField{}
	err := m.Body.Get(f)
	return f, err
}

//GetProductComplex reads a ProductComplex from CollateralInquiry.
func (m Message) GetProductComplex(f *field.ProductComplexField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceUnitOfMeasure is a non-required field for CollateralInquiry.
func (m Message) PriceUnitOfMeasure() (*field.PriceUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.PriceUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceUnitOfMeasure reads a PriceUnitOfMeasure from CollateralInquiry.
func (m Message) GetPriceUnitOfMeasure(f *field.PriceUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceUnitOfMeasureQty is a non-required field for CollateralInquiry.
func (m Message) PriceUnitOfMeasureQty() (*field.PriceUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.PriceUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceUnitOfMeasureQty reads a PriceUnitOfMeasureQty from CollateralInquiry.
func (m Message) GetPriceUnitOfMeasureQty(f *field.PriceUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlMethod is a non-required field for CollateralInquiry.
func (m Message) SettlMethod() (*field.SettlMethodField, quickfix.MessageRejectError) {
	f := &field.SettlMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlMethod reads a SettlMethod from CollateralInquiry.
func (m Message) GetSettlMethod(f *field.SettlMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExerciseStyle is a non-required field for CollateralInquiry.
func (m Message) ExerciseStyle() (*field.ExerciseStyleField, quickfix.MessageRejectError) {
	f := &field.ExerciseStyleField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExerciseStyle reads a ExerciseStyle from CollateralInquiry.
func (m Message) GetExerciseStyle(f *field.ExerciseStyleField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptPayoutAmount is a non-required field for CollateralInquiry.
func (m Message) OptPayoutAmount() (*field.OptPayoutAmountField, quickfix.MessageRejectError) {
	f := &field.OptPayoutAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptPayoutAmount reads a OptPayoutAmount from CollateralInquiry.
func (m Message) GetOptPayoutAmount(f *field.OptPayoutAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceQuoteMethod is a non-required field for CollateralInquiry.
func (m Message) PriceQuoteMethod() (*field.PriceQuoteMethodField, quickfix.MessageRejectError) {
	f := &field.PriceQuoteMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceQuoteMethod reads a PriceQuoteMethod from CollateralInquiry.
func (m Message) GetPriceQuoteMethod(f *field.PriceQuoteMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ListMethod is a non-required field for CollateralInquiry.
func (m Message) ListMethod() (*field.ListMethodField, quickfix.MessageRejectError) {
	f := &field.ListMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetListMethod reads a ListMethod from CollateralInquiry.
func (m Message) GetListMethod(f *field.ListMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CapPrice is a non-required field for CollateralInquiry.
func (m Message) CapPrice() (*field.CapPriceField, quickfix.MessageRejectError) {
	f := &field.CapPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCapPrice reads a CapPrice from CollateralInquiry.
func (m Message) GetCapPrice(f *field.CapPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FloorPrice is a non-required field for CollateralInquiry.
func (m Message) FloorPrice() (*field.FloorPriceField, quickfix.MessageRejectError) {
	f := &field.FloorPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFloorPrice reads a FloorPrice from CollateralInquiry.
func (m Message) GetFloorPrice(f *field.FloorPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PutOrCall is a non-required field for CollateralInquiry.
func (m Message) PutOrCall() (*field.PutOrCallField, quickfix.MessageRejectError) {
	f := &field.PutOrCallField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPutOrCall reads a PutOrCall from CollateralInquiry.
func (m Message) GetPutOrCall(f *field.PutOrCallField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlexibleIndicator is a non-required field for CollateralInquiry.
func (m Message) FlexibleIndicator() (*field.FlexibleIndicatorField, quickfix.MessageRejectError) {
	f := &field.FlexibleIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlexibleIndicator reads a FlexibleIndicator from CollateralInquiry.
func (m Message) GetFlexibleIndicator(f *field.FlexibleIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlexProductEligibilityIndicator is a non-required field for CollateralInquiry.
func (m Message) FlexProductEligibilityIndicator() (*field.FlexProductEligibilityIndicatorField, quickfix.MessageRejectError) {
	f := &field.FlexProductEligibilityIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlexProductEligibilityIndicator reads a FlexProductEligibilityIndicator from CollateralInquiry.
func (m Message) GetFlexProductEligibilityIndicator(f *field.FlexProductEligibilityIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ValuationMethod is a non-required field for CollateralInquiry.
func (m Message) ValuationMethod() (*field.ValuationMethodField, quickfix.MessageRejectError) {
	f := &field.ValuationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetValuationMethod reads a ValuationMethod from CollateralInquiry.
func (m Message) GetValuationMethod(f *field.ValuationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractMultiplierUnit is a non-required field for CollateralInquiry.
func (m Message) ContractMultiplierUnit() (*field.ContractMultiplierUnitField, quickfix.MessageRejectError) {
	f := &field.ContractMultiplierUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractMultiplierUnit reads a ContractMultiplierUnit from CollateralInquiry.
func (m Message) GetContractMultiplierUnit(f *field.ContractMultiplierUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlowScheduleType is a non-required field for CollateralInquiry.
func (m Message) FlowScheduleType() (*field.FlowScheduleTypeField, quickfix.MessageRejectError) {
	f := &field.FlowScheduleTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlowScheduleType reads a FlowScheduleType from CollateralInquiry.
func (m Message) GetFlowScheduleType(f *field.FlowScheduleTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RestructuringType is a non-required field for CollateralInquiry.
func (m Message) RestructuringType() (*field.RestructuringTypeField, quickfix.MessageRejectError) {
	f := &field.RestructuringTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRestructuringType reads a RestructuringType from CollateralInquiry.
func (m Message) GetRestructuringType(f *field.RestructuringTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Seniority is a non-required field for CollateralInquiry.
func (m Message) Seniority() (*field.SeniorityField, quickfix.MessageRejectError) {
	f := &field.SeniorityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSeniority reads a Seniority from CollateralInquiry.
func (m Message) GetSeniority(f *field.SeniorityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NotionalPercentageOutstanding is a non-required field for CollateralInquiry.
func (m Message) NotionalPercentageOutstanding() (*field.NotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.NotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNotionalPercentageOutstanding reads a NotionalPercentageOutstanding from CollateralInquiry.
func (m Message) GetNotionalPercentageOutstanding(f *field.NotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OriginalNotionalPercentageOutstanding is a non-required field for CollateralInquiry.
func (m Message) OriginalNotionalPercentageOutstanding() (*field.OriginalNotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.OriginalNotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOriginalNotionalPercentageOutstanding reads a OriginalNotionalPercentageOutstanding from CollateralInquiry.
func (m Message) GetOriginalNotionalPercentageOutstanding(f *field.OriginalNotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AttachmentPoint is a non-required field for CollateralInquiry.
func (m Message) AttachmentPoint() (*field.AttachmentPointField, quickfix.MessageRejectError) {
	f := &field.AttachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAttachmentPoint reads a AttachmentPoint from CollateralInquiry.
func (m Message) GetAttachmentPoint(f *field.AttachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DetachmentPoint is a non-required field for CollateralInquiry.
func (m Message) DetachmentPoint() (*field.DetachmentPointField, quickfix.MessageRejectError) {
	f := &field.DetachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDetachmentPoint reads a DetachmentPoint from CollateralInquiry.
func (m Message) GetDetachmentPoint(f *field.DetachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceDeterminationMethod is a non-required field for CollateralInquiry.
func (m Message) StrikePriceDeterminationMethod() (*field.StrikePriceDeterminationMethodField, quickfix.MessageRejectError) {
	f := &field.StrikePriceDeterminationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceDeterminationMethod reads a StrikePriceDeterminationMethod from CollateralInquiry.
func (m Message) GetStrikePriceDeterminationMethod(f *field.StrikePriceDeterminationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceBoundaryMethod is a non-required field for CollateralInquiry.
func (m Message) StrikePriceBoundaryMethod() (*field.StrikePriceBoundaryMethodField, quickfix.MessageRejectError) {
	f := &field.StrikePriceBoundaryMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceBoundaryMethod reads a StrikePriceBoundaryMethod from CollateralInquiry.
func (m Message) GetStrikePriceBoundaryMethod(f *field.StrikePriceBoundaryMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceBoundaryPrecision is a non-required field for CollateralInquiry.
func (m Message) StrikePriceBoundaryPrecision() (*field.StrikePriceBoundaryPrecisionField, quickfix.MessageRejectError) {
	f := &field.StrikePriceBoundaryPrecisionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceBoundaryPrecision reads a StrikePriceBoundaryPrecision from CollateralInquiry.
func (m Message) GetStrikePriceBoundaryPrecision(f *field.StrikePriceBoundaryPrecisionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPriceDeterminationMethod is a non-required field for CollateralInquiry.
func (m Message) UnderlyingPriceDeterminationMethod() (*field.UnderlyingPriceDeterminationMethodField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPriceDeterminationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPriceDeterminationMethod reads a UnderlyingPriceDeterminationMethod from CollateralInquiry.
func (m Message) GetUnderlyingPriceDeterminationMethod(f *field.UnderlyingPriceDeterminationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptPayoutType is a non-required field for CollateralInquiry.
func (m Message) OptPayoutType() (*field.OptPayoutTypeField, quickfix.MessageRejectError) {
	f := &field.OptPayoutTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptPayoutType reads a OptPayoutType from CollateralInquiry.
func (m Message) GetOptPayoutType(f *field.OptPayoutTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoComplexEvents is a non-required field for CollateralInquiry.
func (m Message) NoComplexEvents() (*field.NoComplexEventsField, quickfix.MessageRejectError) {
	f := &field.NoComplexEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoComplexEvents reads a NoComplexEvents from CollateralInquiry.
func (m Message) GetNoComplexEvents(f *field.NoComplexEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementDesc is a non-required field for CollateralInquiry.
func (m Message) AgreementDesc() (*field.AgreementDescField, quickfix.MessageRejectError) {
	f := &field.AgreementDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementDesc reads a AgreementDesc from CollateralInquiry.
func (m Message) GetAgreementDesc(f *field.AgreementDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementID is a non-required field for CollateralInquiry.
func (m Message) AgreementID() (*field.AgreementIDField, quickfix.MessageRejectError) {
	f := &field.AgreementIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementID reads a AgreementID from CollateralInquiry.
func (m Message) GetAgreementID(f *field.AgreementIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementDate is a non-required field for CollateralInquiry.
func (m Message) AgreementDate() (*field.AgreementDateField, quickfix.MessageRejectError) {
	f := &field.AgreementDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementDate reads a AgreementDate from CollateralInquiry.
func (m Message) GetAgreementDate(f *field.AgreementDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AgreementCurrency is a non-required field for CollateralInquiry.
func (m Message) AgreementCurrency() (*field.AgreementCurrencyField, quickfix.MessageRejectError) {
	f := &field.AgreementCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAgreementCurrency reads a AgreementCurrency from CollateralInquiry.
func (m Message) GetAgreementCurrency(f *field.AgreementCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TerminationType is a non-required field for CollateralInquiry.
func (m Message) TerminationType() (*field.TerminationTypeField, quickfix.MessageRejectError) {
	f := &field.TerminationTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTerminationType reads a TerminationType from CollateralInquiry.
func (m Message) GetTerminationType(f *field.TerminationTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StartDate is a non-required field for CollateralInquiry.
func (m Message) StartDate() (*field.StartDateField, quickfix.MessageRejectError) {
	f := &field.StartDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStartDate reads a StartDate from CollateralInquiry.
func (m Message) GetStartDate(f *field.StartDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EndDate is a non-required field for CollateralInquiry.
func (m Message) EndDate() (*field.EndDateField, quickfix.MessageRejectError) {
	f := &field.EndDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEndDate reads a EndDate from CollateralInquiry.
func (m Message) GetEndDate(f *field.EndDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DeliveryType is a non-required field for CollateralInquiry.
func (m Message) DeliveryType() (*field.DeliveryTypeField, quickfix.MessageRejectError) {
	f := &field.DeliveryTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDeliveryType reads a DeliveryType from CollateralInquiry.
func (m Message) GetDeliveryType(f *field.DeliveryTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MarginRatio is a non-required field for CollateralInquiry.
func (m Message) MarginRatio() (*field.MarginRatioField, quickfix.MessageRejectError) {
	f := &field.MarginRatioField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMarginRatio reads a MarginRatio from CollateralInquiry.
func (m Message) GetMarginRatio(f *field.MarginRatioField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlDate is a non-required field for CollateralInquiry.
func (m Message) SettlDate() (*field.SettlDateField, quickfix.MessageRejectError) {
	f := &field.SettlDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlDate reads a SettlDate from CollateralInquiry.
func (m Message) GetSettlDate(f *field.SettlDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Quantity is a non-required field for CollateralInquiry.
func (m Message) Quantity() (*field.QuantityField, quickfix.MessageRejectError) {
	f := &field.QuantityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetQuantity reads a Quantity from CollateralInquiry.
func (m Message) GetQuantity(f *field.QuantityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//QtyType is a non-required field for CollateralInquiry.
func (m Message) QtyType() (*field.QtyTypeField, quickfix.MessageRejectError) {
	f := &field.QtyTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetQtyType reads a QtyType from CollateralInquiry.
func (m Message) GetQtyType(f *field.QtyTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Currency is a non-required field for CollateralInquiry.
func (m Message) Currency() (*field.CurrencyField, quickfix.MessageRejectError) {
	f := &field.CurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCurrency reads a Currency from CollateralInquiry.
func (m Message) GetCurrency(f *field.CurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoLegs is a non-required field for CollateralInquiry.
func (m Message) NoLegs() (*field.NoLegsField, quickfix.MessageRejectError) {
	f := &field.NoLegsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoLegs reads a NoLegs from CollateralInquiry.
func (m Message) GetNoLegs(f *field.NoLegsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUnderlyings is a non-required field for CollateralInquiry.
func (m Message) NoUnderlyings() (*field.NoUnderlyingsField, quickfix.MessageRejectError) {
	f := &field.NoUnderlyingsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUnderlyings reads a NoUnderlyings from CollateralInquiry.
func (m Message) GetNoUnderlyings(f *field.NoUnderlyingsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MarginExcess is a non-required field for CollateralInquiry.
func (m Message) MarginExcess() (*field.MarginExcessField, quickfix.MessageRejectError) {
	f := &field.MarginExcessField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMarginExcess reads a MarginExcess from CollateralInquiry.
func (m Message) GetMarginExcess(f *field.MarginExcessField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TotalNetValue is a non-required field for CollateralInquiry.
func (m Message) TotalNetValue() (*field.TotalNetValueField, quickfix.MessageRejectError) {
	f := &field.TotalNetValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTotalNetValue reads a TotalNetValue from CollateralInquiry.
func (m Message) GetTotalNetValue(f *field.TotalNetValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CashOutstanding is a non-required field for CollateralInquiry.
func (m Message) CashOutstanding() (*field.CashOutstandingField, quickfix.MessageRejectError) {
	f := &field.CashOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCashOutstanding reads a CashOutstanding from CollateralInquiry.
func (m Message) GetCashOutstanding(f *field.CashOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoTrdRegTimestamps is a non-required field for CollateralInquiry.
func (m Message) NoTrdRegTimestamps() (*field.NoTrdRegTimestampsField, quickfix.MessageRejectError) {
	f := &field.NoTrdRegTimestampsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoTrdRegTimestamps reads a NoTrdRegTimestamps from CollateralInquiry.
func (m Message) GetNoTrdRegTimestamps(f *field.NoTrdRegTimestampsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Side is a non-required field for CollateralInquiry.
func (m Message) Side() (*field.SideField, quickfix.MessageRejectError) {
	f := &field.SideField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSide reads a Side from CollateralInquiry.
func (m Message) GetSide(f *field.SideField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Price is a non-required field for CollateralInquiry.
func (m Message) Price() (*field.PriceField, quickfix.MessageRejectError) {
	f := &field.PriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPrice reads a Price from CollateralInquiry.
func (m Message) GetPrice(f *field.PriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceType is a non-required field for CollateralInquiry.
func (m Message) PriceType() (*field.PriceTypeField, quickfix.MessageRejectError) {
	f := &field.PriceTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceType reads a PriceType from CollateralInquiry.
func (m Message) GetPriceType(f *field.PriceTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AccruedInterestAmt is a non-required field for CollateralInquiry.
func (m Message) AccruedInterestAmt() (*field.AccruedInterestAmtField, quickfix.MessageRejectError) {
	f := &field.AccruedInterestAmtField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccruedInterestAmt reads a AccruedInterestAmt from CollateralInquiry.
func (m Message) GetAccruedInterestAmt(f *field.AccruedInterestAmtField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EndAccruedInterestAmt is a non-required field for CollateralInquiry.
func (m Message) EndAccruedInterestAmt() (*field.EndAccruedInterestAmtField, quickfix.MessageRejectError) {
	f := &field.EndAccruedInterestAmtField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEndAccruedInterestAmt reads a EndAccruedInterestAmt from CollateralInquiry.
func (m Message) GetEndAccruedInterestAmt(f *field.EndAccruedInterestAmtField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StartCash is a non-required field for CollateralInquiry.
func (m Message) StartCash() (*field.StartCashField, quickfix.MessageRejectError) {
	f := &field.StartCashField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStartCash reads a StartCash from CollateralInquiry.
func (m Message) GetStartCash(f *field.StartCashField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EndCash is a non-required field for CollateralInquiry.
func (m Message) EndCash() (*field.EndCashField, quickfix.MessageRejectError) {
	f := &field.EndCashField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEndCash reads a EndCash from CollateralInquiry.
func (m Message) GetEndCash(f *field.EndCashField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Spread is a non-required field for CollateralInquiry.
func (m Message) Spread() (*field.SpreadField, quickfix.MessageRejectError) {
	f := &field.SpreadField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSpread reads a Spread from CollateralInquiry.
func (m Message) GetSpread(f *field.SpreadField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurveCurrency is a non-required field for CollateralInquiry.
func (m Message) BenchmarkCurveCurrency() (*field.BenchmarkCurveCurrencyField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurveCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurveCurrency reads a BenchmarkCurveCurrency from CollateralInquiry.
func (m Message) GetBenchmarkCurveCurrency(f *field.BenchmarkCurveCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurveName is a non-required field for CollateralInquiry.
func (m Message) BenchmarkCurveName() (*field.BenchmarkCurveNameField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurveNameField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurveName reads a BenchmarkCurveName from CollateralInquiry.
func (m Message) GetBenchmarkCurveName(f *field.BenchmarkCurveNameField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkCurvePoint is a non-required field for CollateralInquiry.
func (m Message) BenchmarkCurvePoint() (*field.BenchmarkCurvePointField, quickfix.MessageRejectError) {
	f := &field.BenchmarkCurvePointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkCurvePoint reads a BenchmarkCurvePoint from CollateralInquiry.
func (m Message) GetBenchmarkCurvePoint(f *field.BenchmarkCurvePointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkPrice is a non-required field for CollateralInquiry.
func (m Message) BenchmarkPrice() (*field.BenchmarkPriceField, quickfix.MessageRejectError) {
	f := &field.BenchmarkPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkPrice reads a BenchmarkPrice from CollateralInquiry.
func (m Message) GetBenchmarkPrice(f *field.BenchmarkPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkPriceType is a non-required field for CollateralInquiry.
func (m Message) BenchmarkPriceType() (*field.BenchmarkPriceTypeField, quickfix.MessageRejectError) {
	f := &field.BenchmarkPriceTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkPriceType reads a BenchmarkPriceType from CollateralInquiry.
func (m Message) GetBenchmarkPriceType(f *field.BenchmarkPriceTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkSecurityID is a non-required field for CollateralInquiry.
func (m Message) BenchmarkSecurityID() (*field.BenchmarkSecurityIDField, quickfix.MessageRejectError) {
	f := &field.BenchmarkSecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkSecurityID reads a BenchmarkSecurityID from CollateralInquiry.
func (m Message) GetBenchmarkSecurityID(f *field.BenchmarkSecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//BenchmarkSecurityIDSource is a non-required field for CollateralInquiry.
func (m Message) BenchmarkSecurityIDSource() (*field.BenchmarkSecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.BenchmarkSecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetBenchmarkSecurityIDSource reads a BenchmarkSecurityIDSource from CollateralInquiry.
func (m Message) GetBenchmarkSecurityIDSource(f *field.BenchmarkSecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoStipulations is a non-required field for CollateralInquiry.
func (m Message) NoStipulations() (*field.NoStipulationsField, quickfix.MessageRejectError) {
	f := &field.NoStipulationsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoStipulations reads a NoStipulations from CollateralInquiry.
func (m Message) GetNoStipulations(f *field.NoStipulationsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlDeliveryType is a non-required field for CollateralInquiry.
func (m Message) SettlDeliveryType() (*field.SettlDeliveryTypeField, quickfix.MessageRejectError) {
	f := &field.SettlDeliveryTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlDeliveryType reads a SettlDeliveryType from CollateralInquiry.
func (m Message) GetSettlDeliveryType(f *field.SettlDeliveryTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StandInstDbType is a non-required field for CollateralInquiry.
func (m Message) StandInstDbType() (*field.StandInstDbTypeField, quickfix.MessageRejectError) {
	f := &field.StandInstDbTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStandInstDbType reads a StandInstDbType from CollateralInquiry.
func (m Message) GetStandInstDbType(f *field.StandInstDbTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StandInstDbName is a non-required field for CollateralInquiry.
func (m Message) StandInstDbName() (*field.StandInstDbNameField, quickfix.MessageRejectError) {
	f := &field.StandInstDbNameField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStandInstDbName reads a StandInstDbName from CollateralInquiry.
func (m Message) GetStandInstDbName(f *field.StandInstDbNameField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StandInstDbID is a non-required field for CollateralInquiry.
func (m Message) StandInstDbID() (*field.StandInstDbIDField, quickfix.MessageRejectError) {
	f := &field.StandInstDbIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStandInstDbID reads a StandInstDbID from CollateralInquiry.
func (m Message) GetStandInstDbID(f *field.StandInstDbIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoDlvyInst is a non-required field for CollateralInquiry.
func (m Message) NoDlvyInst() (*field.NoDlvyInstField, quickfix.MessageRejectError) {
	f := &field.NoDlvyInstField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoDlvyInst reads a NoDlvyInst from CollateralInquiry.
func (m Message) GetNoDlvyInst(f *field.NoDlvyInstField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradingSessionID is a non-required field for CollateralInquiry.
func (m Message) TradingSessionID() (*field.TradingSessionIDField, quickfix.MessageRejectError) {
	f := &field.TradingSessionIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradingSessionID reads a TradingSessionID from CollateralInquiry.
func (m Message) GetTradingSessionID(f *field.TradingSessionIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradingSessionSubID is a non-required field for CollateralInquiry.
func (m Message) TradingSessionSubID() (*field.TradingSessionSubIDField, quickfix.MessageRejectError) {
	f := &field.TradingSessionSubIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradingSessionSubID reads a TradingSessionSubID from CollateralInquiry.
func (m Message) GetTradingSessionSubID(f *field.TradingSessionSubIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlSessID is a non-required field for CollateralInquiry.
func (m Message) SettlSessID() (*field.SettlSessIDField, quickfix.MessageRejectError) {
	f := &field.SettlSessIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlSessID reads a SettlSessID from CollateralInquiry.
func (m Message) GetSettlSessID(f *field.SettlSessIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlSessSubID is a non-required field for CollateralInquiry.
func (m Message) SettlSessSubID() (*field.SettlSessSubIDField, quickfix.MessageRejectError) {
	f := &field.SettlSessSubIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlSessSubID reads a SettlSessSubID from CollateralInquiry.
func (m Message) GetSettlSessSubID(f *field.SettlSessSubIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClearingBusinessDate is a non-required field for CollateralInquiry.
func (m Message) ClearingBusinessDate() (*field.ClearingBusinessDateField, quickfix.MessageRejectError) {
	f := &field.ClearingBusinessDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClearingBusinessDate reads a ClearingBusinessDate from CollateralInquiry.
func (m Message) GetClearingBusinessDate(f *field.ClearingBusinessDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for CollateralInquiry.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from CollateralInquiry.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedTextLen is a non-required field for CollateralInquiry.
func (m Message) EncodedTextLen() (*field.EncodedTextLenField, quickfix.MessageRejectError) {
	f := &field.EncodedTextLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedTextLen reads a EncodedTextLen from CollateralInquiry.
func (m Message) GetEncodedTextLen(f *field.EncodedTextLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedText is a non-required field for CollateralInquiry.
func (m Message) EncodedText() (*field.EncodedTextField, quickfix.MessageRejectError) {
	f := &field.EncodedTextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedText reads a EncodedText from CollateralInquiry.
func (m Message) GetEncodedText(f *field.EncodedTextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for CollateralInquiry.
func New(
	collinquiryid *field.CollInquiryIDField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIXT11))
	builder.Header.Set(field.NewDefaultApplVerID(enum.ApplVerID_FIX50SP2))
	builder.Header.Set(field.NewMsgType("BB"))
	builder.Body.Set(collinquiryid)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.ApplVerID_FIX50SP2, "BB", r
}
