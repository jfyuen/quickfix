package quickfix

import (
	"crypto/tls"
	"fmt"
	"github.com/quickfixgo/quickfix/config"
	"net"
	"strings"
	"errors"
)

//Initiator initiates connections and processes messages for all sessions.
type Initiator struct {
	app             Application
	settings        *Settings
	sessionSettings map[SessionID]*SessionSettings
	storeFactory    MessageStoreFactory
	logFactory      LogFactory
	globalLog       Log
	quitChans       map[SessionID]chan bool
}

func readConfig(s *SessionSettings, cfg string) []string {
	sslProtocols, err := s.Setting(cfg)
	if err != nil {
		return make([]string, 0)
	}
	choices := make([]string, 1)
	for _, proto := range strings.Split(sslProtocols, ",") {
		proto = strings.TrimSpace(proto)
		choices = append(choices, proto)
	}
	return choices
}

func getSSLProtocol(s string) (uint16, error) {
	s = strings.ToLower(s)
	switch s {
	case "ssl3", "sslv3":
		return tls.VersionSSL30, nil
	case "tlsv1", "tls1":
		return tls.VersionTLS10, nil
	case "tls11", "tlsv1.1", "tls1.1":
		return tls.VersionTLS11, nil
	case "tls12", "tlsv1.2", "tls1.2":
		return tls.VersionTLS11, nil
	default:
		return 0, errors.New(s + " not found in SSL versions")
	}
}

func readSSLProtocols(s *SessionSettings) ([]uint16, error) {
	protos := readConfig(s, config.SSLProtocols)
	r := make([]uint16, len(protos), len(protos))
	for i, s := range protos {
		if c, err := getSSLProtocol(s); err != nil {
			return nil, err
		} else {
			r[i] = c
		}
	}
	return r, nil
}

func getCipher(s string) (uint16, error) {
	switch s {
	case "TLS_RSA_WITH_RC4_128_SHA":
		return tls.TLS_RSA_WITH_RC4_128_SHA, nil
	case "TLS_RSA_WITH_3DES_EDE_CBC_SHA":
		return tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_RC4_128_SHA":
		return tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, nil
	case "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, nil
	case "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, nil
	case "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, nil
	case "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":
		return tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, nil
	default:
		return 0, errors.New(s + " cipher not found")
	}
}

func readCiphers(s *SessionSettings) ([]uint16, error) {
	ciphers := readConfig(s, config.CipherSuites)
	r := make([]uint16, len(ciphers), len(ciphers))
	for i, s := range ciphers {
		if c, err := getCipher(s); err != nil {
			return nil, err
		} else {
			r[i] = c
		}
	}
	return r, nil
}

func findMinMax(s []uint16) (uint16, uint16) {
	minVersion := s[0]
	maxVersion := s[0]
	for _, v := range s {
		if v > maxVersion {
			maxVersion = v
		} else if v < minVersion {
			minVersion = v
		}
	}
	return minVersion, maxVersion
}

func (i *Initiator) openConnection(s *SessionSettings, addr string) (net.Conn, error) {
	if socketUseSSL, err := s.Setting(config.SocketUseSSL); err != nil {
		return nil, err
	} else if socketUseSSL != "Y" {
		i.globalLog.OnEvent("Not using encrypted connection")
		return net.Dial("tcp", addr)
	}

	availableProtos, err := readSSLProtocols(s)
	if err != nil {
		return nil, err
	}

	cyphers, err := readCiphers(s)
	if err != nil {
		return nil, err
	}

	minSSLVersion, maxSSLVersion := findMinMax(availableProtos)
	c := &tls.Config{CipherSuites: cyphers, MinVersion: minSSLVersion, MaxVersion: maxSSLVersion}
	i.globalLog.OnEvent("Using encrypted connection")
	return tls.Dial("tcp", addr, c)
}

//Start Initiator.
func (i *Initiator) Start() error {

	for sessionID, s := range i.sessionSettings {
		socketConnectHost, err := s.Setting(config.SocketConnectHost)
		if err != nil {
			return fmt.Errorf("error on SocketConnectHost: %v", err)
		}

		socketConnectPort, err := s.IntSetting(config.SocketConnectPort)
		if err != nil {
			return fmt.Errorf("error on SocketConnectPort: %v", err)
		}

		addr := fmt.Sprintf("%v:%v", socketConnectHost, socketConnectPort)
		conn, err := i.openConnection(s, addr)
		if err != nil {
			return err
		}

		i.quitChans[sessionID] = make(chan bool)
		go handleInitiatorConnection(conn, i.globalLog, sessionID, i.quitChans[sessionID])
	}

	return nil
}

//Stop Initiator.
func (i *Initiator) Stop() {
	defer func() {
		_ = recover() // suppress sending on closed channel error
	}()
	for _, channel := range i.quitChans {
		channel <- true
	}
}

//NewInitiator creates and initializes a new Initiator.
func NewInitiator(app Application, storeFactory MessageStoreFactory, appSettings *Settings, logFactory LogFactory) (*Initiator, error) {
	i := new(Initiator)
	i.app = app
	i.storeFactory = storeFactory
	i.settings = appSettings
	i.sessionSettings = appSettings.SessionSettings()
	i.logFactory = logFactory
	i.quitChans = make(map[SessionID]chan bool)

	var err error
	i.globalLog, err = logFactory.Create()
	if err != nil {
		return i, err
	}

	for sessionID, s := range i.sessionSettings {

		//fail fast
		if ok := s.HasSetting(config.SocketConnectHost); !ok {
			return nil, requiredConfigurationMissing(config.SocketConnectHost)
		}

		if ok := s.HasSetting(config.SocketConnectPort); !ok {
			return nil, requiredConfigurationMissing(config.SocketConnectPort)
		}

		err = createSession(sessionID, storeFactory, s, logFactory, app)
		if err != nil {
			return nil, err
		}
	}

	return i, nil
}
