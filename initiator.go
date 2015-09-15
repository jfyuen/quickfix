package quickfix

import (
	"crypto/tls"
	"fmt"
	"github.com/quickfixgo/quickfix/config"
	"net"
	"strings"
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

func (i *Initiator) openConnection(s *SessionSettings, addr string) (net.Conn, error) {
	if socketUseSSL, err := s.Setting(config.SocketUseSSL); err == nil && socketUseSSL == "Y" {
		sslProtocols, err := s.Setting(config.SSLProtocols)
		if err != nil {
			return nil, fmt.Errorf("error on SSLProtocols: %v", err)
		}
		availableProtos := make([]string, 1)
		for _, proto := range strings.Split(sslProtocols, ",") {
			proto = strings.TrimSpace(proto)
			availableProtos = append(availableProtos, proto)
		}
		for _, proto := range availableProtos {
			switch proto {
			case "TLSv1":
				i.globalLog.OnEvent("Using protocol TLSv1")
				return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
			}
		}
		return nil, fmt.Errorf("No suitable protocol found in : %v", availableProtos)
	}
	i.globalLog.OnEvent("Using no encryption")
	return net.Dial("tcp", addr)
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
