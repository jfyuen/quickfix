//Package positionmaintenancereport msg type = AM.
package positionmaintenancereport

import (
	"github.com/quickfixgo/quickfix"
	"github.com/quickfixgo/quickfix/fix"
	"github.com/quickfixgo/quickfix/fix/field"
)

import (
	"github.com/quickfixgo/quickfix/fix/enum"
)

//Message is a PositionMaintenanceReport wrapper for the generic Message type
type Message struct {
	quickfix.Message
}

//PosMaintRptID is a required field for PositionMaintenanceReport.
func (m Message) PosMaintRptID() (*field.PosMaintRptIDField, quickfix.MessageRejectError) {
	f := &field.PosMaintRptIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosMaintRptID reads a PosMaintRptID from PositionMaintenanceReport.
func (m Message) GetPosMaintRptID(f *field.PosMaintRptIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosTransType is a required field for PositionMaintenanceReport.
func (m Message) PosTransType() (*field.PosTransTypeField, quickfix.MessageRejectError) {
	f := &field.PosTransTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosTransType reads a PosTransType from PositionMaintenanceReport.
func (m Message) GetPosTransType(f *field.PosTransTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosReqID is a non-required field for PositionMaintenanceReport.
func (m Message) PosReqID() (*field.PosReqIDField, quickfix.MessageRejectError) {
	f := &field.PosReqIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosReqID reads a PosReqID from PositionMaintenanceReport.
func (m Message) GetPosReqID(f *field.PosReqIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosMaintAction is a required field for PositionMaintenanceReport.
func (m Message) PosMaintAction() (*field.PosMaintActionField, quickfix.MessageRejectError) {
	f := &field.PosMaintActionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosMaintAction reads a PosMaintAction from PositionMaintenanceReport.
func (m Message) GetPosMaintAction(f *field.PosMaintActionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OrigPosReqRefID is a non-required field for PositionMaintenanceReport.
func (m Message) OrigPosReqRefID() (*field.OrigPosReqRefIDField, quickfix.MessageRejectError) {
	f := &field.OrigPosReqRefIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOrigPosReqRefID reads a OrigPosReqRefID from PositionMaintenanceReport.
func (m Message) GetOrigPosReqRefID(f *field.OrigPosReqRefIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosMaintStatus is a required field for PositionMaintenanceReport.
func (m Message) PosMaintStatus() (*field.PosMaintStatusField, quickfix.MessageRejectError) {
	f := &field.PosMaintStatusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosMaintStatus reads a PosMaintStatus from PositionMaintenanceReport.
func (m Message) GetPosMaintStatus(f *field.PosMaintStatusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosMaintResult is a non-required field for PositionMaintenanceReport.
func (m Message) PosMaintResult() (*field.PosMaintResultField, quickfix.MessageRejectError) {
	f := &field.PosMaintResultField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosMaintResult reads a PosMaintResult from PositionMaintenanceReport.
func (m Message) GetPosMaintResult(f *field.PosMaintResultField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ClearingBusinessDate is a required field for PositionMaintenanceReport.
func (m Message) ClearingBusinessDate() (*field.ClearingBusinessDateField, quickfix.MessageRejectError) {
	f := &field.ClearingBusinessDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetClearingBusinessDate reads a ClearingBusinessDate from PositionMaintenanceReport.
func (m Message) GetClearingBusinessDate(f *field.ClearingBusinessDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlSessID is a non-required field for PositionMaintenanceReport.
func (m Message) SettlSessID() (*field.SettlSessIDField, quickfix.MessageRejectError) {
	f := &field.SettlSessIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlSessID reads a SettlSessID from PositionMaintenanceReport.
func (m Message) GetSettlSessID(f *field.SettlSessIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlSessSubID is a non-required field for PositionMaintenanceReport.
func (m Message) SettlSessSubID() (*field.SettlSessSubIDField, quickfix.MessageRejectError) {
	f := &field.SettlSessSubIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlSessSubID reads a SettlSessSubID from PositionMaintenanceReport.
func (m Message) GetSettlSessSubID(f *field.SettlSessSubIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPartyIDs is a non-required field for PositionMaintenanceReport.
func (m Message) NoPartyIDs() (*field.NoPartyIDsField, quickfix.MessageRejectError) {
	f := &field.NoPartyIDsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPartyIDs reads a NoPartyIDs from PositionMaintenanceReport.
func (m Message) GetNoPartyIDs(f *field.NoPartyIDsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Account is a non-required field for PositionMaintenanceReport.
func (m Message) Account() (*field.AccountField, quickfix.MessageRejectError) {
	f := &field.AccountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccount reads a Account from PositionMaintenanceReport.
func (m Message) GetAccount(f *field.AccountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AcctIDSource is a non-required field for PositionMaintenanceReport.
func (m Message) AcctIDSource() (*field.AcctIDSourceField, quickfix.MessageRejectError) {
	f := &field.AcctIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAcctIDSource reads a AcctIDSource from PositionMaintenanceReport.
func (m Message) GetAcctIDSource(f *field.AcctIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AccountType is a non-required field for PositionMaintenanceReport.
func (m Message) AccountType() (*field.AccountTypeField, quickfix.MessageRejectError) {
	f := &field.AccountTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAccountType reads a AccountType from PositionMaintenanceReport.
func (m Message) GetAccountType(f *field.AccountTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Symbol is a non-required field for PositionMaintenanceReport.
func (m Message) Symbol() (*field.SymbolField, quickfix.MessageRejectError) {
	f := &field.SymbolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbol reads a Symbol from PositionMaintenanceReport.
func (m Message) GetSymbol(f *field.SymbolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SymbolSfx is a non-required field for PositionMaintenanceReport.
func (m Message) SymbolSfx() (*field.SymbolSfxField, quickfix.MessageRejectError) {
	f := &field.SymbolSfxField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSymbolSfx reads a SymbolSfx from PositionMaintenanceReport.
func (m Message) GetSymbolSfx(f *field.SymbolSfxField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityID is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityID() (*field.SecurityIDField, quickfix.MessageRejectError) {
	f := &field.SecurityIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityID reads a SecurityID from PositionMaintenanceReport.
func (m Message) GetSecurityID(f *field.SecurityIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityIDSource is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityIDSource() (*field.SecurityIDSourceField, quickfix.MessageRejectError) {
	f := &field.SecurityIDSourceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityIDSource reads a SecurityIDSource from PositionMaintenanceReport.
func (m Message) GetSecurityIDSource(f *field.SecurityIDSourceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoSecurityAltID is a non-required field for PositionMaintenanceReport.
func (m Message) NoSecurityAltID() (*field.NoSecurityAltIDField, quickfix.MessageRejectError) {
	f := &field.NoSecurityAltIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoSecurityAltID reads a NoSecurityAltID from PositionMaintenanceReport.
func (m Message) GetNoSecurityAltID(f *field.NoSecurityAltIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Product is a non-required field for PositionMaintenanceReport.
func (m Message) Product() (*field.ProductField, quickfix.MessageRejectError) {
	f := &field.ProductField{}
	err := m.Body.Get(f)
	return f, err
}

//GetProduct reads a Product from PositionMaintenanceReport.
func (m Message) GetProduct(f *field.ProductField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CFICode is a non-required field for PositionMaintenanceReport.
func (m Message) CFICode() (*field.CFICodeField, quickfix.MessageRejectError) {
	f := &field.CFICodeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCFICode reads a CFICode from PositionMaintenanceReport.
func (m Message) GetCFICode(f *field.CFICodeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityType is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityType() (*field.SecurityTypeField, quickfix.MessageRejectError) {
	f := &field.SecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityType reads a SecurityType from PositionMaintenanceReport.
func (m Message) GetSecurityType(f *field.SecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecuritySubType is a non-required field for PositionMaintenanceReport.
func (m Message) SecuritySubType() (*field.SecuritySubTypeField, quickfix.MessageRejectError) {
	f := &field.SecuritySubTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecuritySubType reads a SecuritySubType from PositionMaintenanceReport.
func (m Message) GetSecuritySubType(f *field.SecuritySubTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityMonthYear is a non-required field for PositionMaintenanceReport.
func (m Message) MaturityMonthYear() (*field.MaturityMonthYearField, quickfix.MessageRejectError) {
	f := &field.MaturityMonthYearField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityMonthYear reads a MaturityMonthYear from PositionMaintenanceReport.
func (m Message) GetMaturityMonthYear(f *field.MaturityMonthYearField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityDate is a non-required field for PositionMaintenanceReport.
func (m Message) MaturityDate() (*field.MaturityDateField, quickfix.MessageRejectError) {
	f := &field.MaturityDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityDate reads a MaturityDate from PositionMaintenanceReport.
func (m Message) GetMaturityDate(f *field.MaturityDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponPaymentDate is a non-required field for PositionMaintenanceReport.
func (m Message) CouponPaymentDate() (*field.CouponPaymentDateField, quickfix.MessageRejectError) {
	f := &field.CouponPaymentDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponPaymentDate reads a CouponPaymentDate from PositionMaintenanceReport.
func (m Message) GetCouponPaymentDate(f *field.CouponPaymentDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//IssueDate is a non-required field for PositionMaintenanceReport.
func (m Message) IssueDate() (*field.IssueDateField, quickfix.MessageRejectError) {
	f := &field.IssueDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssueDate reads a IssueDate from PositionMaintenanceReport.
func (m Message) GetIssueDate(f *field.IssueDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepoCollateralSecurityType is a non-required field for PositionMaintenanceReport.
func (m Message) RepoCollateralSecurityType() (*field.RepoCollateralSecurityTypeField, quickfix.MessageRejectError) {
	f := &field.RepoCollateralSecurityTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepoCollateralSecurityType reads a RepoCollateralSecurityType from PositionMaintenanceReport.
func (m Message) GetRepoCollateralSecurityType(f *field.RepoCollateralSecurityTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseTerm is a non-required field for PositionMaintenanceReport.
func (m Message) RepurchaseTerm() (*field.RepurchaseTermField, quickfix.MessageRejectError) {
	f := &field.RepurchaseTermField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseTerm reads a RepurchaseTerm from PositionMaintenanceReport.
func (m Message) GetRepurchaseTerm(f *field.RepurchaseTermField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RepurchaseRate is a non-required field for PositionMaintenanceReport.
func (m Message) RepurchaseRate() (*field.RepurchaseRateField, quickfix.MessageRejectError) {
	f := &field.RepurchaseRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRepurchaseRate reads a RepurchaseRate from PositionMaintenanceReport.
func (m Message) GetRepurchaseRate(f *field.RepurchaseRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Factor is a non-required field for PositionMaintenanceReport.
func (m Message) Factor() (*field.FactorField, quickfix.MessageRejectError) {
	f := &field.FactorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFactor reads a Factor from PositionMaintenanceReport.
func (m Message) GetFactor(f *field.FactorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CreditRating is a non-required field for PositionMaintenanceReport.
func (m Message) CreditRating() (*field.CreditRatingField, quickfix.MessageRejectError) {
	f := &field.CreditRatingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCreditRating reads a CreditRating from PositionMaintenanceReport.
func (m Message) GetCreditRating(f *field.CreditRatingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InstrRegistry is a non-required field for PositionMaintenanceReport.
func (m Message) InstrRegistry() (*field.InstrRegistryField, quickfix.MessageRejectError) {
	f := &field.InstrRegistryField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInstrRegistry reads a InstrRegistry from PositionMaintenanceReport.
func (m Message) GetInstrRegistry(f *field.InstrRegistryField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CountryOfIssue is a non-required field for PositionMaintenanceReport.
func (m Message) CountryOfIssue() (*field.CountryOfIssueField, quickfix.MessageRejectError) {
	f := &field.CountryOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCountryOfIssue reads a CountryOfIssue from PositionMaintenanceReport.
func (m Message) GetCountryOfIssue(f *field.CountryOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StateOrProvinceOfIssue is a non-required field for PositionMaintenanceReport.
func (m Message) StateOrProvinceOfIssue() (*field.StateOrProvinceOfIssueField, quickfix.MessageRejectError) {
	f := &field.StateOrProvinceOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStateOrProvinceOfIssue reads a StateOrProvinceOfIssue from PositionMaintenanceReport.
func (m Message) GetStateOrProvinceOfIssue(f *field.StateOrProvinceOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//LocaleOfIssue is a non-required field for PositionMaintenanceReport.
func (m Message) LocaleOfIssue() (*field.LocaleOfIssueField, quickfix.MessageRejectError) {
	f := &field.LocaleOfIssueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetLocaleOfIssue reads a LocaleOfIssue from PositionMaintenanceReport.
func (m Message) GetLocaleOfIssue(f *field.LocaleOfIssueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RedemptionDate is a non-required field for PositionMaintenanceReport.
func (m Message) RedemptionDate() (*field.RedemptionDateField, quickfix.MessageRejectError) {
	f := &field.RedemptionDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRedemptionDate reads a RedemptionDate from PositionMaintenanceReport.
func (m Message) GetRedemptionDate(f *field.RedemptionDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePrice is a non-required field for PositionMaintenanceReport.
func (m Message) StrikePrice() (*field.StrikePriceField, quickfix.MessageRejectError) {
	f := &field.StrikePriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePrice reads a StrikePrice from PositionMaintenanceReport.
func (m Message) GetStrikePrice(f *field.StrikePriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeCurrency is a non-required field for PositionMaintenanceReport.
func (m Message) StrikeCurrency() (*field.StrikeCurrencyField, quickfix.MessageRejectError) {
	f := &field.StrikeCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeCurrency reads a StrikeCurrency from PositionMaintenanceReport.
func (m Message) GetStrikeCurrency(f *field.StrikeCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptAttribute is a non-required field for PositionMaintenanceReport.
func (m Message) OptAttribute() (*field.OptAttributeField, quickfix.MessageRejectError) {
	f := &field.OptAttributeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptAttribute reads a OptAttribute from PositionMaintenanceReport.
func (m Message) GetOptAttribute(f *field.OptAttributeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractMultiplier is a non-required field for PositionMaintenanceReport.
func (m Message) ContractMultiplier() (*field.ContractMultiplierField, quickfix.MessageRejectError) {
	f := &field.ContractMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractMultiplier reads a ContractMultiplier from PositionMaintenanceReport.
func (m Message) GetContractMultiplier(f *field.ContractMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CouponRate is a non-required field for PositionMaintenanceReport.
func (m Message) CouponRate() (*field.CouponRateField, quickfix.MessageRejectError) {
	f := &field.CouponRateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCouponRate reads a CouponRate from PositionMaintenanceReport.
func (m Message) GetCouponRate(f *field.CouponRateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityExchange is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityExchange() (*field.SecurityExchangeField, quickfix.MessageRejectError) {
	f := &field.SecurityExchangeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityExchange reads a SecurityExchange from PositionMaintenanceReport.
func (m Message) GetSecurityExchange(f *field.SecurityExchangeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Issuer is a non-required field for PositionMaintenanceReport.
func (m Message) Issuer() (*field.IssuerField, quickfix.MessageRejectError) {
	f := &field.IssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetIssuer reads a Issuer from PositionMaintenanceReport.
func (m Message) GetIssuer(f *field.IssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuerLen is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedIssuerLen() (*field.EncodedIssuerLenField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuerLen reads a EncodedIssuerLen from PositionMaintenanceReport.
func (m Message) GetEncodedIssuerLen(f *field.EncodedIssuerLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedIssuer is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedIssuer() (*field.EncodedIssuerField, quickfix.MessageRejectError) {
	f := &field.EncodedIssuerField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedIssuer reads a EncodedIssuer from PositionMaintenanceReport.
func (m Message) GetEncodedIssuer(f *field.EncodedIssuerField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityDesc is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityDesc() (*field.SecurityDescField, quickfix.MessageRejectError) {
	f := &field.SecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityDesc reads a SecurityDesc from PositionMaintenanceReport.
func (m Message) GetSecurityDesc(f *field.SecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDescLen is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedSecurityDescLen() (*field.EncodedSecurityDescLenField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDescLen reads a EncodedSecurityDescLen from PositionMaintenanceReport.
func (m Message) GetEncodedSecurityDescLen(f *field.EncodedSecurityDescLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedSecurityDesc is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedSecurityDesc() (*field.EncodedSecurityDescField, quickfix.MessageRejectError) {
	f := &field.EncodedSecurityDescField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedSecurityDesc reads a EncodedSecurityDesc from PositionMaintenanceReport.
func (m Message) GetEncodedSecurityDesc(f *field.EncodedSecurityDescField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Pool is a non-required field for PositionMaintenanceReport.
func (m Message) Pool() (*field.PoolField, quickfix.MessageRejectError) {
	f := &field.PoolField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPool reads a Pool from PositionMaintenanceReport.
func (m Message) GetPool(f *field.PoolField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractSettlMonth is a non-required field for PositionMaintenanceReport.
func (m Message) ContractSettlMonth() (*field.ContractSettlMonthField, quickfix.MessageRejectError) {
	f := &field.ContractSettlMonthField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractSettlMonth reads a ContractSettlMonth from PositionMaintenanceReport.
func (m Message) GetContractSettlMonth(f *field.ContractSettlMonthField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPProgram is a non-required field for PositionMaintenanceReport.
func (m Message) CPProgram() (*field.CPProgramField, quickfix.MessageRejectError) {
	f := &field.CPProgramField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPProgram reads a CPProgram from PositionMaintenanceReport.
func (m Message) GetCPProgram(f *field.CPProgramField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CPRegType is a non-required field for PositionMaintenanceReport.
func (m Message) CPRegType() (*field.CPRegTypeField, quickfix.MessageRejectError) {
	f := &field.CPRegTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCPRegType reads a CPRegType from PositionMaintenanceReport.
func (m Message) GetCPRegType(f *field.CPRegTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoEvents is a non-required field for PositionMaintenanceReport.
func (m Message) NoEvents() (*field.NoEventsField, quickfix.MessageRejectError) {
	f := &field.NoEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoEvents reads a NoEvents from PositionMaintenanceReport.
func (m Message) GetNoEvents(f *field.NoEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DatedDate is a non-required field for PositionMaintenanceReport.
func (m Message) DatedDate() (*field.DatedDateField, quickfix.MessageRejectError) {
	f := &field.DatedDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDatedDate reads a DatedDate from PositionMaintenanceReport.
func (m Message) GetDatedDate(f *field.DatedDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InterestAccrualDate is a non-required field for PositionMaintenanceReport.
func (m Message) InterestAccrualDate() (*field.InterestAccrualDateField, quickfix.MessageRejectError) {
	f := &field.InterestAccrualDateField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInterestAccrualDate reads a InterestAccrualDate from PositionMaintenanceReport.
func (m Message) GetInterestAccrualDate(f *field.InterestAccrualDateField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityStatus is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityStatus() (*field.SecurityStatusField, quickfix.MessageRejectError) {
	f := &field.SecurityStatusField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityStatus reads a SecurityStatus from PositionMaintenanceReport.
func (m Message) GetSecurityStatus(f *field.SecurityStatusField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettleOnOpenFlag is a non-required field for PositionMaintenanceReport.
func (m Message) SettleOnOpenFlag() (*field.SettleOnOpenFlagField, quickfix.MessageRejectError) {
	f := &field.SettleOnOpenFlagField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettleOnOpenFlag reads a SettleOnOpenFlag from PositionMaintenanceReport.
func (m Message) GetSettleOnOpenFlag(f *field.SettleOnOpenFlagField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//InstrmtAssignmentMethod is a non-required field for PositionMaintenanceReport.
func (m Message) InstrmtAssignmentMethod() (*field.InstrmtAssignmentMethodField, quickfix.MessageRejectError) {
	f := &field.InstrmtAssignmentMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetInstrmtAssignmentMethod reads a InstrmtAssignmentMethod from PositionMaintenanceReport.
func (m Message) GetInstrmtAssignmentMethod(f *field.InstrmtAssignmentMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeMultiplier is a non-required field for PositionMaintenanceReport.
func (m Message) StrikeMultiplier() (*field.StrikeMultiplierField, quickfix.MessageRejectError) {
	f := &field.StrikeMultiplierField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeMultiplier reads a StrikeMultiplier from PositionMaintenanceReport.
func (m Message) GetStrikeMultiplier(f *field.StrikeMultiplierField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikeValue is a non-required field for PositionMaintenanceReport.
func (m Message) StrikeValue() (*field.StrikeValueField, quickfix.MessageRejectError) {
	f := &field.StrikeValueField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikeValue reads a StrikeValue from PositionMaintenanceReport.
func (m Message) GetStrikeValue(f *field.StrikeValueField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MinPriceIncrement is a non-required field for PositionMaintenanceReport.
func (m Message) MinPriceIncrement() (*field.MinPriceIncrementField, quickfix.MessageRejectError) {
	f := &field.MinPriceIncrementField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMinPriceIncrement reads a MinPriceIncrement from PositionMaintenanceReport.
func (m Message) GetMinPriceIncrement(f *field.MinPriceIncrementField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PositionLimit is a non-required field for PositionMaintenanceReport.
func (m Message) PositionLimit() (*field.PositionLimitField, quickfix.MessageRejectError) {
	f := &field.PositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPositionLimit reads a PositionLimit from PositionMaintenanceReport.
func (m Message) GetPositionLimit(f *field.PositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NTPositionLimit is a non-required field for PositionMaintenanceReport.
func (m Message) NTPositionLimit() (*field.NTPositionLimitField, quickfix.MessageRejectError) {
	f := &field.NTPositionLimitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNTPositionLimit reads a NTPositionLimit from PositionMaintenanceReport.
func (m Message) GetNTPositionLimit(f *field.NTPositionLimitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoInstrumentParties is a non-required field for PositionMaintenanceReport.
func (m Message) NoInstrumentParties() (*field.NoInstrumentPartiesField, quickfix.MessageRejectError) {
	f := &field.NoInstrumentPartiesField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoInstrumentParties reads a NoInstrumentParties from PositionMaintenanceReport.
func (m Message) GetNoInstrumentParties(f *field.NoInstrumentPartiesField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnitOfMeasure is a non-required field for PositionMaintenanceReport.
func (m Message) UnitOfMeasure() (*field.UnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.UnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnitOfMeasure reads a UnitOfMeasure from PositionMaintenanceReport.
func (m Message) GetUnitOfMeasure(f *field.UnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TimeUnit is a non-required field for PositionMaintenanceReport.
func (m Message) TimeUnit() (*field.TimeUnitField, quickfix.MessageRejectError) {
	f := &field.TimeUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTimeUnit reads a TimeUnit from PositionMaintenanceReport.
func (m Message) GetTimeUnit(f *field.TimeUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MaturityTime is a non-required field for PositionMaintenanceReport.
func (m Message) MaturityTime() (*field.MaturityTimeField, quickfix.MessageRejectError) {
	f := &field.MaturityTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMaturityTime reads a MaturityTime from PositionMaintenanceReport.
func (m Message) GetMaturityTime(f *field.MaturityTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityGroup is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityGroup() (*field.SecurityGroupField, quickfix.MessageRejectError) {
	f := &field.SecurityGroupField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityGroup reads a SecurityGroup from PositionMaintenanceReport.
func (m Message) GetSecurityGroup(f *field.SecurityGroupField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//MinPriceIncrementAmount is a non-required field for PositionMaintenanceReport.
func (m Message) MinPriceIncrementAmount() (*field.MinPriceIncrementAmountField, quickfix.MessageRejectError) {
	f := &field.MinPriceIncrementAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetMinPriceIncrementAmount reads a MinPriceIncrementAmount from PositionMaintenanceReport.
func (m Message) GetMinPriceIncrementAmount(f *field.MinPriceIncrementAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnitOfMeasureQty is a non-required field for PositionMaintenanceReport.
func (m Message) UnitOfMeasureQty() (*field.UnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.UnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnitOfMeasureQty reads a UnitOfMeasureQty from PositionMaintenanceReport.
func (m Message) GetUnitOfMeasureQty(f *field.UnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXMLLen is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityXMLLen() (*field.SecurityXMLLenField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXMLLen reads a SecurityXMLLen from PositionMaintenanceReport.
func (m Message) GetSecurityXMLLen(f *field.SecurityXMLLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXML is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityXML() (*field.SecurityXMLField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXML reads a SecurityXML from PositionMaintenanceReport.
func (m Message) GetSecurityXML(f *field.SecurityXMLField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SecurityXMLSchema is a non-required field for PositionMaintenanceReport.
func (m Message) SecurityXMLSchema() (*field.SecurityXMLSchemaField, quickfix.MessageRejectError) {
	f := &field.SecurityXMLSchemaField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSecurityXMLSchema reads a SecurityXMLSchema from PositionMaintenanceReport.
func (m Message) GetSecurityXMLSchema(f *field.SecurityXMLSchemaField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ProductComplex is a non-required field for PositionMaintenanceReport.
func (m Message) ProductComplex() (*field.ProductComplexField, quickfix.MessageRejectError) {
	f := &field.ProductComplexField{}
	err := m.Body.Get(f)
	return f, err
}

//GetProductComplex reads a ProductComplex from PositionMaintenanceReport.
func (m Message) GetProductComplex(f *field.ProductComplexField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceUnitOfMeasure is a non-required field for PositionMaintenanceReport.
func (m Message) PriceUnitOfMeasure() (*field.PriceUnitOfMeasureField, quickfix.MessageRejectError) {
	f := &field.PriceUnitOfMeasureField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceUnitOfMeasure reads a PriceUnitOfMeasure from PositionMaintenanceReport.
func (m Message) GetPriceUnitOfMeasure(f *field.PriceUnitOfMeasureField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceUnitOfMeasureQty is a non-required field for PositionMaintenanceReport.
func (m Message) PriceUnitOfMeasureQty() (*field.PriceUnitOfMeasureQtyField, quickfix.MessageRejectError) {
	f := &field.PriceUnitOfMeasureQtyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceUnitOfMeasureQty reads a PriceUnitOfMeasureQty from PositionMaintenanceReport.
func (m Message) GetPriceUnitOfMeasureQty(f *field.PriceUnitOfMeasureQtyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlMethod is a non-required field for PositionMaintenanceReport.
func (m Message) SettlMethod() (*field.SettlMethodField, quickfix.MessageRejectError) {
	f := &field.SettlMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlMethod reads a SettlMethod from PositionMaintenanceReport.
func (m Message) GetSettlMethod(f *field.SettlMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ExerciseStyle is a non-required field for PositionMaintenanceReport.
func (m Message) ExerciseStyle() (*field.ExerciseStyleField, quickfix.MessageRejectError) {
	f := &field.ExerciseStyleField{}
	err := m.Body.Get(f)
	return f, err
}

//GetExerciseStyle reads a ExerciseStyle from PositionMaintenanceReport.
func (m Message) GetExerciseStyle(f *field.ExerciseStyleField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptPayoutAmount is a non-required field for PositionMaintenanceReport.
func (m Message) OptPayoutAmount() (*field.OptPayoutAmountField, quickfix.MessageRejectError) {
	f := &field.OptPayoutAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptPayoutAmount reads a OptPayoutAmount from PositionMaintenanceReport.
func (m Message) GetOptPayoutAmount(f *field.OptPayoutAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriceQuoteMethod is a non-required field for PositionMaintenanceReport.
func (m Message) PriceQuoteMethod() (*field.PriceQuoteMethodField, quickfix.MessageRejectError) {
	f := &field.PriceQuoteMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriceQuoteMethod reads a PriceQuoteMethod from PositionMaintenanceReport.
func (m Message) GetPriceQuoteMethod(f *field.PriceQuoteMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ListMethod is a non-required field for PositionMaintenanceReport.
func (m Message) ListMethod() (*field.ListMethodField, quickfix.MessageRejectError) {
	f := &field.ListMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetListMethod reads a ListMethod from PositionMaintenanceReport.
func (m Message) GetListMethod(f *field.ListMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//CapPrice is a non-required field for PositionMaintenanceReport.
func (m Message) CapPrice() (*field.CapPriceField, quickfix.MessageRejectError) {
	f := &field.CapPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCapPrice reads a CapPrice from PositionMaintenanceReport.
func (m Message) GetCapPrice(f *field.CapPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FloorPrice is a non-required field for PositionMaintenanceReport.
func (m Message) FloorPrice() (*field.FloorPriceField, quickfix.MessageRejectError) {
	f := &field.FloorPriceField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFloorPrice reads a FloorPrice from PositionMaintenanceReport.
func (m Message) GetFloorPrice(f *field.FloorPriceField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PutOrCall is a non-required field for PositionMaintenanceReport.
func (m Message) PutOrCall() (*field.PutOrCallField, quickfix.MessageRejectError) {
	f := &field.PutOrCallField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPutOrCall reads a PutOrCall from PositionMaintenanceReport.
func (m Message) GetPutOrCall(f *field.PutOrCallField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlexibleIndicator is a non-required field for PositionMaintenanceReport.
func (m Message) FlexibleIndicator() (*field.FlexibleIndicatorField, quickfix.MessageRejectError) {
	f := &field.FlexibleIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlexibleIndicator reads a FlexibleIndicator from PositionMaintenanceReport.
func (m Message) GetFlexibleIndicator(f *field.FlexibleIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlexProductEligibilityIndicator is a non-required field for PositionMaintenanceReport.
func (m Message) FlexProductEligibilityIndicator() (*field.FlexProductEligibilityIndicatorField, quickfix.MessageRejectError) {
	f := &field.FlexProductEligibilityIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlexProductEligibilityIndicator reads a FlexProductEligibilityIndicator from PositionMaintenanceReport.
func (m Message) GetFlexProductEligibilityIndicator(f *field.FlexProductEligibilityIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ValuationMethod is a non-required field for PositionMaintenanceReport.
func (m Message) ValuationMethod() (*field.ValuationMethodField, quickfix.MessageRejectError) {
	f := &field.ValuationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetValuationMethod reads a ValuationMethod from PositionMaintenanceReport.
func (m Message) GetValuationMethod(f *field.ValuationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContractMultiplierUnit is a non-required field for PositionMaintenanceReport.
func (m Message) ContractMultiplierUnit() (*field.ContractMultiplierUnitField, quickfix.MessageRejectError) {
	f := &field.ContractMultiplierUnitField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContractMultiplierUnit reads a ContractMultiplierUnit from PositionMaintenanceReport.
func (m Message) GetContractMultiplierUnit(f *field.ContractMultiplierUnitField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//FlowScheduleType is a non-required field for PositionMaintenanceReport.
func (m Message) FlowScheduleType() (*field.FlowScheduleTypeField, quickfix.MessageRejectError) {
	f := &field.FlowScheduleTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetFlowScheduleType reads a FlowScheduleType from PositionMaintenanceReport.
func (m Message) GetFlowScheduleType(f *field.FlowScheduleTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//RestructuringType is a non-required field for PositionMaintenanceReport.
func (m Message) RestructuringType() (*field.RestructuringTypeField, quickfix.MessageRejectError) {
	f := &field.RestructuringTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetRestructuringType reads a RestructuringType from PositionMaintenanceReport.
func (m Message) GetRestructuringType(f *field.RestructuringTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Seniority is a non-required field for PositionMaintenanceReport.
func (m Message) Seniority() (*field.SeniorityField, quickfix.MessageRejectError) {
	f := &field.SeniorityField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSeniority reads a Seniority from PositionMaintenanceReport.
func (m Message) GetSeniority(f *field.SeniorityField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NotionalPercentageOutstanding is a non-required field for PositionMaintenanceReport.
func (m Message) NotionalPercentageOutstanding() (*field.NotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.NotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNotionalPercentageOutstanding reads a NotionalPercentageOutstanding from PositionMaintenanceReport.
func (m Message) GetNotionalPercentageOutstanding(f *field.NotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OriginalNotionalPercentageOutstanding is a non-required field for PositionMaintenanceReport.
func (m Message) OriginalNotionalPercentageOutstanding() (*field.OriginalNotionalPercentageOutstandingField, quickfix.MessageRejectError) {
	f := &field.OriginalNotionalPercentageOutstandingField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOriginalNotionalPercentageOutstanding reads a OriginalNotionalPercentageOutstanding from PositionMaintenanceReport.
func (m Message) GetOriginalNotionalPercentageOutstanding(f *field.OriginalNotionalPercentageOutstandingField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AttachmentPoint is a non-required field for PositionMaintenanceReport.
func (m Message) AttachmentPoint() (*field.AttachmentPointField, quickfix.MessageRejectError) {
	f := &field.AttachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAttachmentPoint reads a AttachmentPoint from PositionMaintenanceReport.
func (m Message) GetAttachmentPoint(f *field.AttachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//DetachmentPoint is a non-required field for PositionMaintenanceReport.
func (m Message) DetachmentPoint() (*field.DetachmentPointField, quickfix.MessageRejectError) {
	f := &field.DetachmentPointField{}
	err := m.Body.Get(f)
	return f, err
}

//GetDetachmentPoint reads a DetachmentPoint from PositionMaintenanceReport.
func (m Message) GetDetachmentPoint(f *field.DetachmentPointField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceDeterminationMethod is a non-required field for PositionMaintenanceReport.
func (m Message) StrikePriceDeterminationMethod() (*field.StrikePriceDeterminationMethodField, quickfix.MessageRejectError) {
	f := &field.StrikePriceDeterminationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceDeterminationMethod reads a StrikePriceDeterminationMethod from PositionMaintenanceReport.
func (m Message) GetStrikePriceDeterminationMethod(f *field.StrikePriceDeterminationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceBoundaryMethod is a non-required field for PositionMaintenanceReport.
func (m Message) StrikePriceBoundaryMethod() (*field.StrikePriceBoundaryMethodField, quickfix.MessageRejectError) {
	f := &field.StrikePriceBoundaryMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceBoundaryMethod reads a StrikePriceBoundaryMethod from PositionMaintenanceReport.
func (m Message) GetStrikePriceBoundaryMethod(f *field.StrikePriceBoundaryMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//StrikePriceBoundaryPrecision is a non-required field for PositionMaintenanceReport.
func (m Message) StrikePriceBoundaryPrecision() (*field.StrikePriceBoundaryPrecisionField, quickfix.MessageRejectError) {
	f := &field.StrikePriceBoundaryPrecisionField{}
	err := m.Body.Get(f)
	return f, err
}

//GetStrikePriceBoundaryPrecision reads a StrikePriceBoundaryPrecision from PositionMaintenanceReport.
func (m Message) GetStrikePriceBoundaryPrecision(f *field.StrikePriceBoundaryPrecisionField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//UnderlyingPriceDeterminationMethod is a non-required field for PositionMaintenanceReport.
func (m Message) UnderlyingPriceDeterminationMethod() (*field.UnderlyingPriceDeterminationMethodField, quickfix.MessageRejectError) {
	f := &field.UnderlyingPriceDeterminationMethodField{}
	err := m.Body.Get(f)
	return f, err
}

//GetUnderlyingPriceDeterminationMethod reads a UnderlyingPriceDeterminationMethod from PositionMaintenanceReport.
func (m Message) GetUnderlyingPriceDeterminationMethod(f *field.UnderlyingPriceDeterminationMethodField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//OptPayoutType is a non-required field for PositionMaintenanceReport.
func (m Message) OptPayoutType() (*field.OptPayoutTypeField, quickfix.MessageRejectError) {
	f := &field.OptPayoutTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetOptPayoutType reads a OptPayoutType from PositionMaintenanceReport.
func (m Message) GetOptPayoutType(f *field.OptPayoutTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoComplexEvents is a non-required field for PositionMaintenanceReport.
func (m Message) NoComplexEvents() (*field.NoComplexEventsField, quickfix.MessageRejectError) {
	f := &field.NoComplexEventsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoComplexEvents reads a NoComplexEvents from PositionMaintenanceReport.
func (m Message) GetNoComplexEvents(f *field.NoComplexEventsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Currency is a non-required field for PositionMaintenanceReport.
func (m Message) Currency() (*field.CurrencyField, quickfix.MessageRejectError) {
	f := &field.CurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetCurrency reads a Currency from PositionMaintenanceReport.
func (m Message) GetCurrency(f *field.CurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoLegs is a non-required field for PositionMaintenanceReport.
func (m Message) NoLegs() (*field.NoLegsField, quickfix.MessageRejectError) {
	f := &field.NoLegsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoLegs reads a NoLegs from PositionMaintenanceReport.
func (m Message) GetNoLegs(f *field.NoLegsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoUnderlyings is a non-required field for PositionMaintenanceReport.
func (m Message) NoUnderlyings() (*field.NoUnderlyingsField, quickfix.MessageRejectError) {
	f := &field.NoUnderlyingsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoUnderlyings reads a NoUnderlyings from PositionMaintenanceReport.
func (m Message) GetNoUnderlyings(f *field.NoUnderlyingsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoTradingSessions is a non-required field for PositionMaintenanceReport.
func (m Message) NoTradingSessions() (*field.NoTradingSessionsField, quickfix.MessageRejectError) {
	f := &field.NoTradingSessionsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoTradingSessions reads a NoTradingSessions from PositionMaintenanceReport.
func (m Message) GetNoTradingSessions(f *field.NoTradingSessionsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//TransactTime is a non-required field for PositionMaintenanceReport.
func (m Message) TransactTime() (*field.TransactTimeField, quickfix.MessageRejectError) {
	f := &field.TransactTimeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetTransactTime reads a TransactTime from PositionMaintenanceReport.
func (m Message) GetTransactTime(f *field.TransactTimeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPositions is a non-required field for PositionMaintenanceReport.
func (m Message) NoPositions() (*field.NoPositionsField, quickfix.MessageRejectError) {
	f := &field.NoPositionsField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPositions reads a NoPositions from PositionMaintenanceReport.
func (m Message) GetNoPositions(f *field.NoPositionsField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//NoPosAmt is a non-required field for PositionMaintenanceReport.
func (m Message) NoPosAmt() (*field.NoPosAmtField, quickfix.MessageRejectError) {
	f := &field.NoPosAmtField{}
	err := m.Body.Get(f)
	return f, err
}

//GetNoPosAmt reads a NoPosAmt from PositionMaintenanceReport.
func (m Message) GetNoPosAmt(f *field.NoPosAmtField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//AdjustmentType is a non-required field for PositionMaintenanceReport.
func (m Message) AdjustmentType() (*field.AdjustmentTypeField, quickfix.MessageRejectError) {
	f := &field.AdjustmentTypeField{}
	err := m.Body.Get(f)
	return f, err
}

//GetAdjustmentType reads a AdjustmentType from PositionMaintenanceReport.
func (m Message) GetAdjustmentType(f *field.AdjustmentTypeField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ThresholdAmount is a non-required field for PositionMaintenanceReport.
func (m Message) ThresholdAmount() (*field.ThresholdAmountField, quickfix.MessageRejectError) {
	f := &field.ThresholdAmountField{}
	err := m.Body.Get(f)
	return f, err
}

//GetThresholdAmount reads a ThresholdAmount from PositionMaintenanceReport.
func (m Message) GetThresholdAmount(f *field.ThresholdAmountField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//Text is a non-required field for PositionMaintenanceReport.
func (m Message) Text() (*field.TextField, quickfix.MessageRejectError) {
	f := &field.TextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetText reads a Text from PositionMaintenanceReport.
func (m Message) GetText(f *field.TextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedTextLen is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedTextLen() (*field.EncodedTextLenField, quickfix.MessageRejectError) {
	f := &field.EncodedTextLenField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedTextLen reads a EncodedTextLen from PositionMaintenanceReport.
func (m Message) GetEncodedTextLen(f *field.EncodedTextLenField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//EncodedText is a non-required field for PositionMaintenanceReport.
func (m Message) EncodedText() (*field.EncodedTextField, quickfix.MessageRejectError) {
	f := &field.EncodedTextField{}
	err := m.Body.Get(f)
	return f, err
}

//GetEncodedText reads a EncodedText from PositionMaintenanceReport.
func (m Message) GetEncodedText(f *field.EncodedTextField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//SettlCurrency is a non-required field for PositionMaintenanceReport.
func (m Message) SettlCurrency() (*field.SettlCurrencyField, quickfix.MessageRejectError) {
	f := &field.SettlCurrencyField{}
	err := m.Body.Get(f)
	return f, err
}

//GetSettlCurrency reads a SettlCurrency from PositionMaintenanceReport.
func (m Message) GetSettlCurrency(f *field.SettlCurrencyField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//ContraryInstructionIndicator is a non-required field for PositionMaintenanceReport.
func (m Message) ContraryInstructionIndicator() (*field.ContraryInstructionIndicatorField, quickfix.MessageRejectError) {
	f := &field.ContraryInstructionIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetContraryInstructionIndicator reads a ContraryInstructionIndicator from PositionMaintenanceReport.
func (m Message) GetContraryInstructionIndicator(f *field.ContraryInstructionIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PriorSpreadIndicator is a non-required field for PositionMaintenanceReport.
func (m Message) PriorSpreadIndicator() (*field.PriorSpreadIndicatorField, quickfix.MessageRejectError) {
	f := &field.PriorSpreadIndicatorField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPriorSpreadIndicator reads a PriorSpreadIndicator from PositionMaintenanceReport.
func (m Message) GetPriorSpreadIndicator(f *field.PriorSpreadIndicatorField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//PosMaintRptRefID is a non-required field for PositionMaintenanceReport.
func (m Message) PosMaintRptRefID() (*field.PosMaintRptRefIDField, quickfix.MessageRejectError) {
	f := &field.PosMaintRptRefIDField{}
	err := m.Body.Get(f)
	return f, err
}

//GetPosMaintRptRefID reads a PosMaintRptRefID from PositionMaintenanceReport.
func (m Message) GetPosMaintRptRefID(f *field.PosMaintRptRefIDField) quickfix.MessageRejectError {
	return m.Body.Get(f)
}

//New returns an initialized Message with specified required fields for PositionMaintenanceReport.
func New(
	posmaintrptid *field.PosMaintRptIDField,
	postranstype *field.PosTransTypeField,
	posmaintaction *field.PosMaintActionField,
	posmaintstatus *field.PosMaintStatusField,
	clearingbusinessdate *field.ClearingBusinessDateField) Message {
	builder := Message{Message: quickfix.NewMessage()}
	builder.Header.Set(field.NewBeginString(fix.BeginString_FIXT11))
	builder.Header.Set(field.NewDefaultApplVerID(enum.ApplVerID_FIX50SP2))
	builder.Header.Set(field.NewMsgType("AM"))
	builder.Body.Set(posmaintrptid)
	builder.Body.Set(postranstype)
	builder.Body.Set(posmaintaction)
	builder.Body.Set(posmaintstatus)
	builder.Body.Set(clearingbusinessdate)
	return builder
}

//A RouteOut is the callback type that should be implemented for routing Message
type RouteOut func(msg Message, sessionID quickfix.SessionID) quickfix.MessageRejectError

//Route returns the beginstring, message type, and MessageRoute for this Mesage type
func Route(router RouteOut) (string, string, quickfix.MessageRoute) {
	r := func(msg quickfix.Message, sessionID quickfix.SessionID) quickfix.MessageRejectError {
		return router(Message{msg}, sessionID)
	}
	return enum.ApplVerID_FIX50SP2, "AM", r
}
