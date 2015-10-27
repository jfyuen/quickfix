//Package derivativesecuritylistrequest msg type = z.
package derivativesecuritylistrequest

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

import (
	"github.com/quickfixgo/quickfix/fix/enum"
)

//Message is a DerivativeSecurityListRequest wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//SecurityReqID is a required field for DerivativeSecurityListRequest.
func (m Message) SecurityReqID() (*field.SecurityReqIDField, quickfix.MessageRejectError) {
	f := &field.SecurityReqIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityReqID reads a SecurityReqID from DerivativeSecurityListRequest.
func (m Message) GetSecurityReqID(f *field.SecurityReqIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityListRequestType is a required field for DerivativeSecurityListRequest.
func (m Message) SecurityListRequestType() (*field.SecurityListRequestTypeField, quickfix.MessageRejectError) {
	f := &field.SecurityListRequestTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityListRequestType reads a SecurityListRequestType from DerivativeSecurityListRequest.
func (m Message) GetSecurityListRequestType(f *field.SecurityListRequestTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSymbol is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSymbol() (*field.UnderlyingSymbolField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSymbol reads a UnderlyingSymbol from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSymbol(f *field.UnderlyingSymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSymbolSfx is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSymbolSfx() (*field.UnderlyingSymbolSfxField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSymbolSfx reads a UnderlyingSymbolSfx from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSymbolSfx(f *field.UnderlyingSymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecurityID is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecurityID() (*field.UnderlyingSecurityIDField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecurityID reads a UnderlyingSecurityID from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecurityID(f *field.UnderlyingSecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecurityIDSource is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecurityIDSource() (*field.UnderlyingSecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecurityIDSource reads a UnderlyingSecurityIDSource from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecurityIDSource(f *field.UnderlyingSecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUnderlyingSecurityAltID is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoUnderlyingSecurityAltID() (*field.NoUnderlyingSecurityAltIDField, quickfix.MessageRejectError) {
	f := &field.NoUnderlyingSecurityAltIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUnderlyingSecurityAltID reads a NoUnderlyingSecurityAltID from DerivativeSecurityListRequest.
func (m Message) GetNoUnderlyingSecurityAltID(f *field.NoUnderlyingSecurityAltIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingProduct is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingProduct() (*field.UnderlyingProductField, quickfix.MessageRejectError) {
	f := &field.UnderlyingProductField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingProduct reads a UnderlyingProduct from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingProduct(f *field.UnderlyingProductField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCFICode is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCFICode() (*field.UnderlyingCFICodeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCFICodeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCFICode reads a UnderlyingCFICode from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCFICode(f *field.UnderlyingCFICodeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecurityType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecurityType() (*field.UnderlyingSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecurityType reads a UnderlyingSecurityType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecurityType(f *field.UnderlyingSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecuritySubType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecuritySubType() (*field.UnderlyingSecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecuritySubType reads a UnderlyingSecuritySubType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecuritySubType(f *field.UnderlyingSecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingMaturityMonthYear is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingMaturityMonthYear() (*field.UnderlyingMaturityMonthYearField, quickfix.MessageRejectError) {
	f := &field.UnderlyingMaturityMonthYearField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingMaturityMonthYear reads a UnderlyingMaturityMonthYear from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingMaturityMonthYear(f *field.UnderlyingMaturityMonthYearField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingMaturityDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingMaturityDate() (*field.UnderlyingMaturityDateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingMaturityDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingMaturityDate reads a UnderlyingMaturityDate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingMaturityDate(f *field.UnderlyingMaturityDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCouponPaymentDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCouponPaymentDate() (*field.UnderlyingCouponPaymentDateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCouponPaymentDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCouponPaymentDate reads a UnderlyingCouponPaymentDate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCouponPaymentDate(f *field.UnderlyingCouponPaymentDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingIssueDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingIssueDate() (*field.UnderlyingIssueDateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingIssueDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingIssueDate reads a UnderlyingIssueDate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingIssueDate(f *field.UnderlyingIssueDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingRepoCollateralSecurityType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingRepoCollateralSecurityType() (*field.UnderlyingRepoCollateralSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingRepoCollateralSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingRepoCollateralSecurityType reads a UnderlyingRepoCollateralSecurityType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingRepoCollateralSecurityType(f *field.UnderlyingRepoCollateralSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingRepurchaseTerm is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingRepurchaseTerm() (*field.UnderlyingRepurchaseTermField, quickfix.MessageRejectError) {
	f := &field.UnderlyingRepurchaseTermField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingRepurchaseTerm reads a UnderlyingRepurchaseTerm from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingRepurchaseTerm(f *field.UnderlyingRepurchaseTermField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingRepurchaseRate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingRepurchaseRate() (*field.UnderlyingRepurchaseRateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingRepurchaseRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingRepurchaseRate reads a UnderlyingRepurchaseRate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingRepurchaseRate(f *field.UnderlyingRepurchaseRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingFactor is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingFactor() (*field.UnderlyingFactorField, quickfix.MessageRejectError) {
	f := &field.UnderlyingFactorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingFactor reads a UnderlyingFactor from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingFactor(f *field.UnderlyingFactorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCreditRating is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCreditRating() (*field.UnderlyingCreditRatingField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCreditRatingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCreditRating reads a UnderlyingCreditRating from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCreditRating(f *field.UnderlyingCreditRatingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingInstrRegistry is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingInstrRegistry() (*field.UnderlyingInstrRegistryField, quickfix.MessageRejectError) {
	f := &field.UnderlyingInstrRegistryField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingInstrRegistry reads a UnderlyingInstrRegistry from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingInstrRegistry(f *field.UnderlyingInstrRegistryField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCountryOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCountryOfIssue() (*field.UnderlyingCountryOfIssueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCountryOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCountryOfIssue reads a UnderlyingCountryOfIssue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCountryOfIssue(f *field.UnderlyingCountryOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingStateOrProvinceOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingStateOrProvinceOfIssue() (*field.UnderlyingStateOrProvinceOfIssueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingStateOrProvinceOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingStateOrProvinceOfIssue reads a UnderlyingStateOrProvinceOfIssue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingStateOrProvinceOfIssue(f *field.UnderlyingStateOrProvinceOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingLocaleOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingLocaleOfIssue() (*field.UnderlyingLocaleOfIssueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingLocaleOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingLocaleOfIssue reads a UnderlyingLocaleOfIssue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingLocaleOfIssue(f *field.UnderlyingLocaleOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingRedemptionDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingRedemptionDate() (*field.UnderlyingRedemptionDateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingRedemptionDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingRedemptionDate reads a UnderlyingRedemptionDate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingRedemptionDate(f *field.UnderlyingRedemptionDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingStrikePrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingStrikePrice() (*field.UnderlyingStrikePriceField, quickfix.MessageRejectError) {
	f := &field.UnderlyingStrikePriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingStrikePrice reads a UnderlyingStrikePrice from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingStrikePrice(f *field.UnderlyingStrikePriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingStrikeCurrency is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingStrikeCurrency() (*field.UnderlyingStrikeCurrencyField, quickfix.MessageRejectError) {
	f := &field.UnderlyingStrikeCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingStrikeCurrency reads a UnderlyingStrikeCurrency from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingStrikeCurrency(f *field.UnderlyingStrikeCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingOptAttribute is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingOptAttribute() (*field.UnderlyingOptAttributeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingOptAttributeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingOptAttribute reads a UnderlyingOptAttribute from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingOptAttribute(f *field.UnderlyingOptAttributeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingContractMultiplier is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingContractMultiplier() (*field.UnderlyingContractMultiplierField, quickfix.MessageRejectError) {
	f := &field.UnderlyingContractMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingContractMultiplier reads a UnderlyingContractMultiplier from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingContractMultiplier(f *field.UnderlyingContractMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCouponRate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCouponRate() (*field.UnderlyingCouponRateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCouponRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCouponRate reads a UnderlyingCouponRate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCouponRate(f *field.UnderlyingCouponRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecurityExchange is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecurityExchange() (*field.UnderlyingSecurityExchangeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecurityExchangeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecurityExchange reads a UnderlyingSecurityExchange from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecurityExchange(f *field.UnderlyingSecurityExchangeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingIssuer is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingIssuer() (*field.UnderlyingIssuerField, quickfix.MessageRejectError) {
	f := &field.UnderlyingIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingIssuer reads a UnderlyingIssuer from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingIssuer(f *field.UnderlyingIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedUnderlyingIssuerLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedUnderlyingIssuerLen() (*field.EncodedUnderlyingIssuerLenField, quickfix.MessageRejectError) {
	f := &field.EncodedUnderlyingIssuerLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedUnderlyingIssuerLen reads a EncodedUnderlyingIssuerLen from DerivativeSecurityListRequest.
func (m Message) GetEncodedUnderlyingIssuerLen(f *field.EncodedUnderlyingIssuerLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedUnderlyingIssuer is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedUnderlyingIssuer() (*field.EncodedUnderlyingIssuerField, quickfix.MessageRejectError) {
	f := &field.EncodedUnderlyingIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedUnderlyingIssuer reads a EncodedUnderlyingIssuer from DerivativeSecurityListRequest.
func (m Message) GetEncodedUnderlyingIssuer(f *field.EncodedUnderlyingIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSecurityDesc is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSecurityDesc() (*field.UnderlyingSecurityDescField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSecurityDesc reads a UnderlyingSecurityDesc from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSecurityDesc(f *field.UnderlyingSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedUnderlyingSecurityDescLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedUnderlyingSecurityDescLen() (*field.EncodedUnderlyingSecurityDescLenField, quickfix.MessageRejectError) {
	f := &field.EncodedUnderlyingSecurityDescLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedUnderlyingSecurityDescLen reads a EncodedUnderlyingSecurityDescLen from DerivativeSecurityListRequest.
func (m Message) GetEncodedUnderlyingSecurityDescLen(f *field.EncodedUnderlyingSecurityDescLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedUnderlyingSecurityDesc is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedUnderlyingSecurityDesc() (*field.EncodedUnderlyingSecurityDescField, quickfix.MessageRejectError) {
	f := &field.EncodedUnderlyingSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedUnderlyingSecurityDesc reads a EncodedUnderlyingSecurityDesc from DerivativeSecurityListRequest.
func (m Message) GetEncodedUnderlyingSecurityDesc(f *field.EncodedUnderlyingSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCPProgram is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCPProgram() (*field.UnderlyingCPProgramField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCPProgramField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCPProgram reads a UnderlyingCPProgram from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCPProgram(f *field.UnderlyingCPProgramField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCPRegType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCPRegType() (*field.UnderlyingCPRegTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCPRegTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCPRegType reads a UnderlyingCPRegType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCPRegType(f *field.UnderlyingCPRegTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCurrency is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCurrency() (*field.UnderlyingCurrencyField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCurrency reads a UnderlyingCurrency from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCurrency(f *field.UnderlyingCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingQty is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingQty() (*field.UnderlyingQtyField, quickfix.MessageRejectError) {
	f := &field.UnderlyingQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingQty reads a UnderlyingQty from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingQty(f *field.UnderlyingQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPx is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingPx() (*field.UnderlyingPxField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPx reads a UnderlyingPx from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingPx(f *field.UnderlyingPxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingDirtyPrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingDirtyPrice() (*field.UnderlyingDirtyPriceField, quickfix.MessageRejectError) {
	f := &field.UnderlyingDirtyPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingDirtyPrice reads a UnderlyingDirtyPrice from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingDirtyPrice(f *field.UnderlyingDirtyPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingEndPrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingEndPrice() (*field.UnderlyingEndPriceField, quickfix.MessageRejectError) {
	f := &field.UnderlyingEndPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingEndPrice reads a UnderlyingEndPrice from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingEndPrice(f *field.UnderlyingEndPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingStartValue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingStartValue() (*field.UnderlyingStartValueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingStartValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingStartValue reads a UnderlyingStartValue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingStartValue(f *field.UnderlyingStartValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCurrentValue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCurrentValue() (*field.UnderlyingCurrentValueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCurrentValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCurrentValue reads a UnderlyingCurrentValue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCurrentValue(f *field.UnderlyingCurrentValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingEndValue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingEndValue() (*field.UnderlyingEndValueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingEndValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingEndValue reads a UnderlyingEndValue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingEndValue(f *field.UnderlyingEndValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUnderlyingStips is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoUnderlyingStips() (*field.NoUnderlyingStipsField, quickfix.MessageRejectError) {
	f := &field.NoUnderlyingStipsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUnderlyingStips reads a NoUnderlyingStips from DerivativeSecurityListRequest.
func (m Message) GetNoUnderlyingStips(f *field.NoUnderlyingStipsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingAllocationPercent is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingAllocationPercent() (*field.UnderlyingAllocationPercentField, quickfix.MessageRejectError) {
	f := &field.UnderlyingAllocationPercentField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingAllocationPercent reads a UnderlyingAllocationPercent from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingAllocationPercent(f *field.UnderlyingAllocationPercentField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSettlementType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSettlementType() (*field.UnderlyingSettlementTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSettlementTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSettlementType reads a UnderlyingSettlementType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSettlementType(f *field.UnderlyingSettlementTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCashAmount is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCashAmount() (*field.UnderlyingCashAmountField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCashAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCashAmount reads a UnderlyingCashAmount from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCashAmount(f *field.UnderlyingCashAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCashType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCashType() (*field.UnderlyingCashTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCashTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCashType reads a UnderlyingCashType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCashType(f *field.UnderlyingCashTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingUnitOfMeasure is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingUnitOfMeasure() (*field.UnderlyingUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.UnderlyingUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingUnitOfMeasure reads a UnderlyingUnitOfMeasure from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingUnitOfMeasure(f *field.UnderlyingUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingTimeUnit is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingTimeUnit() (*field.UnderlyingTimeUnitField, quickfix.MessageRejectError) {
	f := &field.UnderlyingTimeUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingTimeUnit reads a UnderlyingTimeUnit from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingTimeUnit(f *field.UnderlyingTimeUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingCapValue is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingCapValue() (*field.UnderlyingCapValueField, quickfix.MessageRejectError) {
	f := &field.UnderlyingCapValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingCapValue reads a UnderlyingCapValue from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingCapValue(f *field.UnderlyingCapValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUndlyInstrumentParties is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoUndlyInstrumentParties() (*field.NoUndlyInstrumentPartiesField, quickfix.MessageRejectError) {
	f := &field.NoUndlyInstrumentPartiesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUndlyInstrumentParties reads a NoUndlyInstrumentParties from DerivativeSecurityListRequest.
func (m Message) GetNoUndlyInstrumentParties(f *field.NoUndlyInstrumentPartiesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSettlMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSettlMethod() (*field.UnderlyingSettlMethodField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSettlMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSettlMethod reads a UnderlyingSettlMethod from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSettlMethod(f *field.UnderlyingSettlMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingAdjustedQuantity is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingAdjustedQuantity() (*field.UnderlyingAdjustedQuantityField, quickfix.MessageRejectError) {
	f := &field.UnderlyingAdjustedQuantityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingAdjustedQuantity reads a UnderlyingAdjustedQuantity from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingAdjustedQuantity(f *field.UnderlyingAdjustedQuantityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingFXRate is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingFXRate() (*field.UnderlyingFXRateField, quickfix.MessageRejectError) {
	f := &field.UnderlyingFXRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingFXRate reads a UnderlyingFXRate from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingFXRate(f *field.UnderlyingFXRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingFXRateCalc is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingFXRateCalc() (*field.UnderlyingFXRateCalcField, quickfix.MessageRejectError) {
	f := &field.UnderlyingFXRateCalcField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingFXRateCalc reads a UnderlyingFXRateCalc from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingFXRateCalc(f *field.UnderlyingFXRateCalcField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingMaturityTime is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingMaturityTime() (*field.UnderlyingMaturityTimeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingMaturityTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingMaturityTime reads a UnderlyingMaturityTime from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingMaturityTime(f *field.UnderlyingMaturityTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPutOrCall is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingPutOrCall() (*field.UnderlyingPutOrCallField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPutOrCallField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPutOrCall reads a UnderlyingPutOrCall from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingPutOrCall(f *field.UnderlyingPutOrCallField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingExerciseStyle is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingExerciseStyle() (*field.UnderlyingExerciseStyleField, quickfix.MessageRejectError) {
	f := &field.UnderlyingExerciseStyleField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingExerciseStyle reads a UnderlyingExerciseStyle from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingExerciseStyle(f *field.UnderlyingExerciseStyleField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingUnitOfMeasureQty is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingUnitOfMeasureQty() (*field.UnderlyingUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.UnderlyingUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingUnitOfMeasureQty reads a UnderlyingUnitOfMeasureQty from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingUnitOfMeasureQty(f *field.UnderlyingUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPriceUnitOfMeasure is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingPriceUnitOfMeasure() (*field.UnderlyingPriceUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPriceUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPriceUnitOfMeasure reads a UnderlyingPriceUnitOfMeasure from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingPriceUnitOfMeasure(f *field.UnderlyingPriceUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPriceUnitOfMeasureQty is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingPriceUnitOfMeasureQty() (*field.UnderlyingPriceUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPriceUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPriceUnitOfMeasureQty reads a UnderlyingPriceUnitOfMeasureQty from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingPriceUnitOfMeasureQty(f *field.UnderlyingPriceUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingContractMultiplierUnit is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingContractMultiplierUnit() (*field.UnderlyingContractMultiplierUnitField, quickfix.MessageRejectError) {
	f := &field.UnderlyingContractMultiplierUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingContractMultiplierUnit reads a UnderlyingContractMultiplierUnit from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingContractMultiplierUnit(f *field.UnderlyingContractMultiplierUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingFlowScheduleType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingFlowScheduleType() (*field.UnderlyingFlowScheduleTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingFlowScheduleTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingFlowScheduleType reads a UnderlyingFlowScheduleType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingFlowScheduleType(f *field.UnderlyingFlowScheduleTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingRestructuringType is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingRestructuringType() (*field.UnderlyingRestructuringTypeField, quickfix.MessageRejectError) {
	f := &field.UnderlyingRestructuringTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingRestructuringType reads a UnderlyingRestructuringType from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingRestructuringType(f *field.UnderlyingRestructuringTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingSeniority is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingSeniority() (*field.UnderlyingSeniorityField, quickfix.MessageRejectError) {
	f := &field.UnderlyingSeniorityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingSeniority reads a UnderlyingSeniority from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingSeniority(f *field.UnderlyingSeniorityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingNotionalPercentageOutstanding is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingNotionalPercentageOutstanding() (*field.UnderlyingNotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.UnderlyingNotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingNotionalPercentageOutstanding reads a UnderlyingNotionalPercentageOutstanding from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingNotionalPercentageOutstanding(f *field.UnderlyingNotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingOriginalNotionalPercentageOutstanding is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingOriginalNotionalPercentageOutstanding() (*field.UnderlyingOriginalNotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.UnderlyingOriginalNotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingOriginalNotionalPercentageOutstanding reads a UnderlyingOriginalNotionalPercentageOutstanding from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingOriginalNotionalPercentageOutstanding(f *field.UnderlyingOriginalNotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingAttachmentPoint is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingAttachmentPoint() (*field.UnderlyingAttachmentPointField, quickfix.MessageRejectError) {
	f := &field.UnderlyingAttachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingAttachmentPoint reads a UnderlyingAttachmentPoint from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingAttachmentPoint(f *field.UnderlyingAttachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingDetachmentPoint is a non-required field for DerivativeSecurityListRequest.
func (m Message) UnderlyingDetachmentPoint() (*field.UnderlyingDetachmentPointField, quickfix.MessageRejectError) {
	f := &field.UnderlyingDetachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingDetachmentPoint reads a UnderlyingDetachmentPoint from DerivativeSecurityListRequest.
func (m Message) GetUnderlyingDetachmentPoint(f *field.UnderlyingDetachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecuritySubType is a non-required field for DerivativeSecurityListRequest.
func (m Message) SecuritySubType() (*field.SecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.SecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecuritySubType reads a SecuritySubType from DerivativeSecurityListRequest.
func (m Message) GetSecuritySubType(f *field.SecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Currency is a non-required field for DerivativeSecurityListRequest.
func (m Message) Currency() (*field.CurrencyField, quickfix.MessageRejectError) {
	f := &field.CurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCurrency reads a Currency from DerivativeSecurityListRequest.
func (m Message) GetCurrency(f *field.CurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for DerivativeSecurityListRequest.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from DerivativeSecurityListRequest.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedTextLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedTextLen() (*field.EncodedTextLenField, quickfix.MessageRejectError) {
	f := &field.EncodedTextLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedTextLen reads a EncodedTextLen from DerivativeSecurityListRequest.
func (m Message) GetEncodedTextLen(f *field.EncodedTextLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedText is a non-required field for DerivativeSecurityListRequest.
func (m Message) EncodedText() (*field.EncodedTextField, quickfix.MessageRejectError) {
	f := &field.EncodedTextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedText reads a EncodedText from DerivativeSecurityListRequest.
func (m Message) GetEncodedText(f *field.EncodedTextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradingSessionID is a non-required field for DerivativeSecurityListRequest.
func (m Message) TradingSessionID() (*field.TradingSessionIDField, quickfix.MessageRejectError) {
	f := &field.TradingSessionIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradingSessionID reads a TradingSessionID from DerivativeSecurityListRequest.
func (m Message) GetTradingSessionID(f *field.TradingSessionIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TradingSessionSubID is a non-required field for DerivativeSecurityListRequest.
func (m Message) TradingSessionSubID() (*field.TradingSessionSubIDField, quickfix.MessageRejectError) {
	f := &field.TradingSessionSubIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTradingSessionSubID reads a TradingSessionSubID from DerivativeSecurityListRequest.
func (m Message) GetTradingSessionSubID(f *field.TradingSessionSubIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SubscriptionRequestType is a non-required field for DerivativeSecurityListRequest.
func (m Message) SubscriptionRequestType() (*field.SubscriptionRequestTypeField, quickfix.MessageRejectError) {
	f := &field.SubscriptionRequestTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSubscriptionRequestType reads a SubscriptionRequestType from DerivativeSecurityListRequest.
func (m Message) GetSubscriptionRequestType(f *field.SubscriptionRequestTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MarketID is a non-required field for DerivativeSecurityListRequest.
func (m Message) MarketID() (*field.MarketIDField, quickfix.MessageRejectError) {
	f := &field.MarketIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMarketID reads a MarketID from DerivativeSecurityListRequest.
func (m Message) GetMarketID(f *field.MarketIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MarketSegmentID is a non-required field for DerivativeSecurityListRequest.
func (m Message) MarketSegmentID() (*field.MarketSegmentIDField, quickfix.MessageRejectError) {
	f := &field.MarketSegmentIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMarketSegmentID reads a MarketSegmentID from DerivativeSecurityListRequest.
func (m Message) GetMarketSegmentID(f *field.MarketSegmentIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSymbol is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSymbol() (*field.DerivativeSymbolField, quickfix.MessageRejectError) {
	f := &field.DerivativeSymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSymbol reads a DerivativeSymbol from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSymbol(f *field.DerivativeSymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSymbolSfx is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSymbolSfx() (*field.DerivativeSymbolSfxField, quickfix.MessageRejectError) {
	f := &field.DerivativeSymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSymbolSfx reads a DerivativeSymbolSfx from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSymbolSfx(f *field.DerivativeSymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityID is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityID() (*field.DerivativeSecurityIDField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityID reads a DerivativeSecurityID from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityID(f *field.DerivativeSecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityIDSource is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityIDSource() (*field.DerivativeSecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityIDSource reads a DerivativeSecurityIDSource from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityIDSource(f *field.DerivativeSecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoDerivativeSecurityAltID is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoDerivativeSecurityAltID() (*field.NoDerivativeSecurityAltIDField, quickfix.MessageRejectError) {
	f := &field.NoDerivativeSecurityAltIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoDerivativeSecurityAltID reads a NoDerivativeSecurityAltID from DerivativeSecurityListRequest.
func (m Message) GetNoDerivativeSecurityAltID(f *field.NoDerivativeSecurityAltIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeProduct is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeProduct() (*field.DerivativeProductField, quickfix.MessageRejectError) {
	f := &field.DerivativeProductField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeProduct reads a DerivativeProduct from DerivativeSecurityListRequest.
func (m Message) GetDerivativeProduct(f *field.DerivativeProductField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeProductComplex is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeProductComplex() (*field.DerivativeProductComplexField, quickfix.MessageRejectError) {
	f := &field.DerivativeProductComplexField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeProductComplex reads a DerivativeProductComplex from DerivativeSecurityListRequest.
func (m Message) GetDerivativeProductComplex(f *field.DerivativeProductComplexField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivFlexProductEligibilityIndicator is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivFlexProductEligibilityIndicator() (*field.DerivFlexProductEligibilityIndicatorField, quickfix.MessageRejectError) {
	f := &field.DerivFlexProductEligibilityIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivFlexProductEligibilityIndicator reads a DerivFlexProductEligibilityIndicator from DerivativeSecurityListRequest.
func (m Message) GetDerivFlexProductEligibilityIndicator(f *field.DerivFlexProductEligibilityIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityGroup is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityGroup() (*field.DerivativeSecurityGroupField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityGroupField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityGroup reads a DerivativeSecurityGroup from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityGroup(f *field.DerivativeSecurityGroupField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeCFICode is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeCFICode() (*field.DerivativeCFICodeField, quickfix.MessageRejectError) {
	f := &field.DerivativeCFICodeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeCFICode reads a DerivativeCFICode from DerivativeSecurityListRequest.
func (m Message) GetDerivativeCFICode(f *field.DerivativeCFICodeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityType is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityType() (*field.DerivativeSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityType reads a DerivativeSecurityType from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityType(f *field.DerivativeSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecuritySubType is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecuritySubType() (*field.DerivativeSecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecuritySubType reads a DerivativeSecuritySubType from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecuritySubType(f *field.DerivativeSecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeMaturityMonthYear is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeMaturityMonthYear() (*field.DerivativeMaturityMonthYearField, quickfix.MessageRejectError) {
	f := &field.DerivativeMaturityMonthYearField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeMaturityMonthYear reads a DerivativeMaturityMonthYear from DerivativeSecurityListRequest.
func (m Message) GetDerivativeMaturityMonthYear(f *field.DerivativeMaturityMonthYearField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeMaturityDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeMaturityDate() (*field.DerivativeMaturityDateField, quickfix.MessageRejectError) {
	f := &field.DerivativeMaturityDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeMaturityDate reads a DerivativeMaturityDate from DerivativeSecurityListRequest.
func (m Message) GetDerivativeMaturityDate(f *field.DerivativeMaturityDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeMaturityTime is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeMaturityTime() (*field.DerivativeMaturityTimeField, quickfix.MessageRejectError) {
	f := &field.DerivativeMaturityTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeMaturityTime reads a DerivativeMaturityTime from DerivativeSecurityListRequest.
func (m Message) GetDerivativeMaturityTime(f *field.DerivativeMaturityTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSettleOnOpenFlag is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSettleOnOpenFlag() (*field.DerivativeSettleOnOpenFlagField, quickfix.MessageRejectError) {
	f := &field.DerivativeSettleOnOpenFlagField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSettleOnOpenFlag reads a DerivativeSettleOnOpenFlag from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSettleOnOpenFlag(f *field.DerivativeSettleOnOpenFlagField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeInstrmtAssignmentMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeInstrmtAssignmentMethod() (*field.DerivativeInstrmtAssignmentMethodField, quickfix.MessageRejectError) {
	f := &field.DerivativeInstrmtAssignmentMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeInstrmtAssignmentMethod reads a DerivativeInstrmtAssignmentMethod from DerivativeSecurityListRequest.
func (m Message) GetDerivativeInstrmtAssignmentMethod(f *field.DerivativeInstrmtAssignmentMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityStatus is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityStatus() (*field.DerivativeSecurityStatusField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityStatusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityStatus reads a DerivativeSecurityStatus from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityStatus(f *field.DerivativeSecurityStatusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeIssueDate is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeIssueDate() (*field.DerivativeIssueDateField, quickfix.MessageRejectError) {
	f := &field.DerivativeIssueDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeIssueDate reads a DerivativeIssueDate from DerivativeSecurityListRequest.
func (m Message) GetDerivativeIssueDate(f *field.DerivativeIssueDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeInstrRegistry is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeInstrRegistry() (*field.DerivativeInstrRegistryField, quickfix.MessageRejectError) {
	f := &field.DerivativeInstrRegistryField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeInstrRegistry reads a DerivativeInstrRegistry from DerivativeSecurityListRequest.
func (m Message) GetDerivativeInstrRegistry(f *field.DerivativeInstrRegistryField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeCountryOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeCountryOfIssue() (*field.DerivativeCountryOfIssueField, quickfix.MessageRejectError) {
	f := &field.DerivativeCountryOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeCountryOfIssue reads a DerivativeCountryOfIssue from DerivativeSecurityListRequest.
func (m Message) GetDerivativeCountryOfIssue(f *field.DerivativeCountryOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeStateOrProvinceOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeStateOrProvinceOfIssue() (*field.DerivativeStateOrProvinceOfIssueField, quickfix.MessageRejectError) {
	f := &field.DerivativeStateOrProvinceOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeStateOrProvinceOfIssue reads a DerivativeStateOrProvinceOfIssue from DerivativeSecurityListRequest.
func (m Message) GetDerivativeStateOrProvinceOfIssue(f *field.DerivativeStateOrProvinceOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeStrikePrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeStrikePrice() (*field.DerivativeStrikePriceField, quickfix.MessageRejectError) {
	f := &field.DerivativeStrikePriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeStrikePrice reads a DerivativeStrikePrice from DerivativeSecurityListRequest.
func (m Message) GetDerivativeStrikePrice(f *field.DerivativeStrikePriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeLocaleOfIssue is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeLocaleOfIssue() (*field.DerivativeLocaleOfIssueField, quickfix.MessageRejectError) {
	f := &field.DerivativeLocaleOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeLocaleOfIssue reads a DerivativeLocaleOfIssue from DerivativeSecurityListRequest.
func (m Message) GetDerivativeLocaleOfIssue(f *field.DerivativeLocaleOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeStrikeCurrency is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeStrikeCurrency() (*field.DerivativeStrikeCurrencyField, quickfix.MessageRejectError) {
	f := &field.DerivativeStrikeCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeStrikeCurrency reads a DerivativeStrikeCurrency from DerivativeSecurityListRequest.
func (m Message) GetDerivativeStrikeCurrency(f *field.DerivativeStrikeCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeStrikeMultiplier is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeStrikeMultiplier() (*field.DerivativeStrikeMultiplierField, quickfix.MessageRejectError) {
	f := &field.DerivativeStrikeMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeStrikeMultiplier reads a DerivativeStrikeMultiplier from DerivativeSecurityListRequest.
func (m Message) GetDerivativeStrikeMultiplier(f *field.DerivativeStrikeMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeStrikeValue is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeStrikeValue() (*field.DerivativeStrikeValueField, quickfix.MessageRejectError) {
	f := &field.DerivativeStrikeValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeStrikeValue reads a DerivativeStrikeValue from DerivativeSecurityListRequest.
func (m Message) GetDerivativeStrikeValue(f *field.DerivativeStrikeValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeOptAttribute is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeOptAttribute() (*field.DerivativeOptAttributeField, quickfix.MessageRejectError) {
	f := &field.DerivativeOptAttributeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeOptAttribute reads a DerivativeOptAttribute from DerivativeSecurityListRequest.
func (m Message) GetDerivativeOptAttribute(f *field.DerivativeOptAttributeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeContractMultiplier is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeContractMultiplier() (*field.DerivativeContractMultiplierField, quickfix.MessageRejectError) {
	f := &field.DerivativeContractMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeContractMultiplier reads a DerivativeContractMultiplier from DerivativeSecurityListRequest.
func (m Message) GetDerivativeContractMultiplier(f *field.DerivativeContractMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeMinPriceIncrement is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeMinPriceIncrement() (*field.DerivativeMinPriceIncrementField, quickfix.MessageRejectError) {
	f := &field.DerivativeMinPriceIncrementField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeMinPriceIncrement reads a DerivativeMinPriceIncrement from DerivativeSecurityListRequest.
func (m Message) GetDerivativeMinPriceIncrement(f *field.DerivativeMinPriceIncrementField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeMinPriceIncrementAmount is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeMinPriceIncrementAmount() (*field.DerivativeMinPriceIncrementAmountField, quickfix.MessageRejectError) {
	f := &field.DerivativeMinPriceIncrementAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeMinPriceIncrementAmount reads a DerivativeMinPriceIncrementAmount from DerivativeSecurityListRequest.
func (m Message) GetDerivativeMinPriceIncrementAmount(f *field.DerivativeMinPriceIncrementAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeUnitOfMeasure is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeUnitOfMeasure() (*field.DerivativeUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.DerivativeUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeUnitOfMeasure reads a DerivativeUnitOfMeasure from DerivativeSecurityListRequest.
func (m Message) GetDerivativeUnitOfMeasure(f *field.DerivativeUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeUnitOfMeasureQty is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeUnitOfMeasureQty() (*field.DerivativeUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.DerivativeUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeUnitOfMeasureQty reads a DerivativeUnitOfMeasureQty from DerivativeSecurityListRequest.
func (m Message) GetDerivativeUnitOfMeasureQty(f *field.DerivativeUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativePriceUnitOfMeasure is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativePriceUnitOfMeasure() (*field.DerivativePriceUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.DerivativePriceUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativePriceUnitOfMeasure reads a DerivativePriceUnitOfMeasure from DerivativeSecurityListRequest.
func (m Message) GetDerivativePriceUnitOfMeasure(f *field.DerivativePriceUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativePriceUnitOfMeasureQty is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativePriceUnitOfMeasureQty() (*field.DerivativePriceUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.DerivativePriceUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativePriceUnitOfMeasureQty reads a DerivativePriceUnitOfMeasureQty from DerivativeSecurityListRequest.
func (m Message) GetDerivativePriceUnitOfMeasureQty(f *field.DerivativePriceUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeExerciseStyle is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeExerciseStyle() (*field.DerivativeExerciseStyleField, quickfix.MessageRejectError) {
	f := &field.DerivativeExerciseStyleField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeExerciseStyle reads a DerivativeExerciseStyle from DerivativeSecurityListRequest.
func (m Message) GetDerivativeExerciseStyle(f *field.DerivativeExerciseStyleField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeOptPayAmount is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeOptPayAmount() (*field.DerivativeOptPayAmountField, quickfix.MessageRejectError) {
	f := &field.DerivativeOptPayAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeOptPayAmount reads a DerivativeOptPayAmount from DerivativeSecurityListRequest.
func (m Message) GetDerivativeOptPayAmount(f *field.DerivativeOptPayAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeTimeUnit is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeTimeUnit() (*field.DerivativeTimeUnitField, quickfix.MessageRejectError) {
	f := &field.DerivativeTimeUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeTimeUnit reads a DerivativeTimeUnit from DerivativeSecurityListRequest.
func (m Message) GetDerivativeTimeUnit(f *field.DerivativeTimeUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityExchange is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityExchange() (*field.DerivativeSecurityExchangeField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityExchangeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityExchange reads a DerivativeSecurityExchange from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityExchange(f *field.DerivativeSecurityExchangeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativePositionLimit is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativePositionLimit() (*field.DerivativePositionLimitField, quickfix.MessageRejectError) {
	f := &field.DerivativePositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativePositionLimit reads a DerivativePositionLimit from DerivativeSecurityListRequest.
func (m Message) GetDerivativePositionLimit(f *field.DerivativePositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeNTPositionLimit is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeNTPositionLimit() (*field.DerivativeNTPositionLimitField, quickfix.MessageRejectError) {
	f := &field.DerivativeNTPositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeNTPositionLimit reads a DerivativeNTPositionLimit from DerivativeSecurityListRequest.
func (m Message) GetDerivativeNTPositionLimit(f *field.DerivativeNTPositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeIssuer is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeIssuer() (*field.DerivativeIssuerField, quickfix.MessageRejectError) {
	f := &field.DerivativeIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeIssuer reads a DerivativeIssuer from DerivativeSecurityListRequest.
func (m Message) GetDerivativeIssuer(f *field.DerivativeIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeEncodedIssuerLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeEncodedIssuerLen() (*field.DerivativeEncodedIssuerLenField, quickfix.MessageRejectError) {
	f := &field.DerivativeEncodedIssuerLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeEncodedIssuerLen reads a DerivativeEncodedIssuerLen from DerivativeSecurityListRequest.
func (m Message) GetDerivativeEncodedIssuerLen(f *field.DerivativeEncodedIssuerLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeEncodedIssuer is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeEncodedIssuer() (*field.DerivativeEncodedIssuerField, quickfix.MessageRejectError) {
	f := &field.DerivativeEncodedIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeEncodedIssuer reads a DerivativeEncodedIssuer from DerivativeSecurityListRequest.
func (m Message) GetDerivativeEncodedIssuer(f *field.DerivativeEncodedIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityDesc is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityDesc() (*field.DerivativeSecurityDescField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityDesc reads a DerivativeSecurityDesc from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityDesc(f *field.DerivativeSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeEncodedSecurityDescLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeEncodedSecurityDescLen() (*field.DerivativeEncodedSecurityDescLenField, quickfix.MessageRejectError) {
	f := &field.DerivativeEncodedSecurityDescLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeEncodedSecurityDescLen reads a DerivativeEncodedSecurityDescLen from DerivativeSecurityListRequest.
func (m Message) GetDerivativeEncodedSecurityDescLen(f *field.DerivativeEncodedSecurityDescLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeEncodedSecurityDesc is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeEncodedSecurityDesc() (*field.DerivativeEncodedSecurityDescField, quickfix.MessageRejectError) {
	f := &field.DerivativeEncodedSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeEncodedSecurityDesc reads a DerivativeEncodedSecurityDesc from DerivativeSecurityListRequest.
func (m Message) GetDerivativeEncodedSecurityDesc(f *field.DerivativeEncodedSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeContractSettlMonth is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeContractSettlMonth() (*field.DerivativeContractSettlMonthField, quickfix.MessageRejectError) {
	f := &field.DerivativeContractSettlMonthField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeContractSettlMonth reads a DerivativeContractSettlMonth from DerivativeSecurityListRequest.
func (m Message) GetDerivativeContractSettlMonth(f *field.DerivativeContractSettlMonthField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoDerivativeEvents is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoDerivativeEvents() (*field.NoDerivativeEventsField, quickfix.MessageRejectError) {
	f := &field.NoDerivativeEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoDerivativeEvents reads a NoDerivativeEvents from DerivativeSecurityListRequest.
func (m Message) GetNoDerivativeEvents(f *field.NoDerivativeEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoDerivativeInstrumentParties is a non-required field for DerivativeSecurityListRequest.
func (m Message) NoDerivativeInstrumentParties() (*field.NoDerivativeInstrumentPartiesField, quickfix.MessageRejectError) {
	f := &field.NoDerivativeInstrumentPartiesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoDerivativeInstrumentParties reads a NoDerivativeInstrumentParties from DerivativeSecurityListRequest.
func (m Message) GetNoDerivativeInstrumentParties(f *field.NoDerivativeInstrumentPartiesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSettlMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSettlMethod() (*field.DerivativeSettlMethodField, quickfix.MessageRejectError) {
	f := &field.DerivativeSettlMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSettlMethod reads a DerivativeSettlMethod from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSettlMethod(f *field.DerivativeSettlMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativePriceQuoteMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativePriceQuoteMethod() (*field.DerivativePriceQuoteMethodField, quickfix.MessageRejectError) {
	f := &field.DerivativePriceQuoteMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativePriceQuoteMethod reads a DerivativePriceQuoteMethod from DerivativeSecurityListRequest.
func (m Message) GetDerivativePriceQuoteMethod(f *field.DerivativePriceQuoteMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeValuationMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeValuationMethod() (*field.DerivativeValuationMethodField, quickfix.MessageRejectError) {
	f := &field.DerivativeValuationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeValuationMethod reads a DerivativeValuationMethod from DerivativeSecurityListRequest.
func (m Message) GetDerivativeValuationMethod(f *field.DerivativeValuationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeListMethod is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeListMethod() (*field.DerivativeListMethodField, quickfix.MessageRejectError) {
	f := &field.DerivativeListMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeListMethod reads a DerivativeListMethod from DerivativeSecurityListRequest.
func (m Message) GetDerivativeListMethod(f *field.DerivativeListMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeCapPrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeCapPrice() (*field.DerivativeCapPriceField, quickfix.MessageRejectError) {
	f := &field.DerivativeCapPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeCapPrice reads a DerivativeCapPrice from DerivativeSecurityListRequest.
func (m Message) GetDerivativeCapPrice(f *field.DerivativeCapPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeFloorPrice is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeFloorPrice() (*field.DerivativeFloorPriceField, quickfix.MessageRejectError) {
	f := &field.DerivativeFloorPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeFloorPrice reads a DerivativeFloorPrice from DerivativeSecurityListRequest.
func (m Message) GetDerivativeFloorPrice(f *field.DerivativeFloorPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativePutOrCall is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativePutOrCall() (*field.DerivativePutOrCallField, quickfix.MessageRejectError) {
	f := &field.DerivativePutOrCallField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativePutOrCall reads a DerivativePutOrCall from DerivativeSecurityListRequest.
func (m Message) GetDerivativePutOrCall(f *field.DerivativePutOrCallField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityXMLLen is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityXMLLen() (*field.DerivativeSecurityXMLLenField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityXMLLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityXMLLen reads a DerivativeSecurityXMLLen from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityXMLLen(f *field.DerivativeSecurityXMLLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityXML is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityXML() (*field.DerivativeSecurityXMLField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityXMLField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityXML reads a DerivativeSecurityXML from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityXML(f *field.DerivativeSecurityXMLField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeSecurityXMLSchema is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeSecurityXMLSchema() (*field.DerivativeSecurityXMLSchemaField, quickfix.MessageRejectError) {
	f := &field.DerivativeSecurityXMLSchemaField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeSecurityXMLSchema reads a DerivativeSecurityXMLSchema from DerivativeSecurityListRequest.
func (m Message) GetDerivativeSecurityXMLSchema(f *field.DerivativeSecurityXMLSchemaField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeContractMultiplierUnit is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeContractMultiplierUnit() (*field.DerivativeContractMultiplierUnitField, quickfix.MessageRejectError) {
	f := &field.DerivativeContractMultiplierUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeContractMultiplierUnit reads a DerivativeContractMultiplierUnit from DerivativeSecurityListRequest.
func (m Message) GetDerivativeContractMultiplierUnit(f *field.DerivativeContractMultiplierUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DerivativeFlowScheduleType is a non-required field for DerivativeSecurityListRequest.
func (m Message) DerivativeFlowScheduleType() (*field.DerivativeFlowScheduleTypeField, quickfix.MessageRejectError) {
	f := &field.DerivativeFlowScheduleTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDerivativeFlowScheduleType reads a DerivativeFlowScheduleType from DerivativeSecurityListRequest.
func (m Message) GetDerivativeFlowScheduleType(f *field.DerivativeFlowScheduleTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for DerivativeSecurityListRequest.
func New(
	securityreqid *field.SecurityReqIDField,
	securitylistrequesttype *field.SecurityListRequestTypeField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIXT11))
	builder.Header.Set(field.NewDefaultApplVerID(enum.ApplVerID_FIX50SP2))
	builder.Header.Set(field.NewMsgType("z"))
	builder.Body.Set(securityreqid)
	builder.Body.Set(securitylistrequesttype)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.ApplVerID_FIX50SP2, "z", r
}
