//Package config declares application and session settings for QuickFIX/Go
package config

const (
	BeginString             string = "BeginString"
	SenderCompID            string = "SenderCompID"
	TargetCompID            string = "TargetCompID"
	SessionQualifier        string = "SessionQualifier"
	SocketAcceptPort        string = "SocketAcceptPort"
	SocketConnectHost       string = "SocketConnectHost"
	SocketConnectPort       string = "SocketConnectPort"
	DefaultApplVerID        string = "DefaultApplVerID"
	DataDictionary          string = "DataDictionary"
	TransportDataDictionary string = "TransportDataDictionary"
	AppDataDictionary       string = "AppDataDictionary"
	ResetOnLogon            string = "ResetOnLogon"
	HeartBtInt              string = "HeartBtInt"
	FileLogPath             string = "FileLogPath"

	// SSl stuff
	SocketUseSSL            string = "SocketUseSSL"
	SSLProtocols            string = "EnabledProtocols"
	SocketKeyStore          string = "SocketKeyStore"
	SocketKeyStorePassword  string = "SocketKeyStorePassword"
	SSLFilter  				string = "SSLFilter"
	CipherSuites			string = "CipherSuites"
)
