package quickfix

type logonState struct{}

func (s logonState) FixMsgIn(session *Session, msg Message) (nextState sessionState) {
	var msgType FIXString
	if err := msg.Header.GetField(tagMsgType, &msgType); err == nil && string(msgType) == "A" {
		if err := session.handleLogon(msg); err != nil {
			session.log.OnEvent(err.Error())
			return latentState{}
		}

		return inSession{}
	}

	session.log.OnEventf("Invalid Session State: Received Msg %v while waiting for Logon", msg)
	return latentState{}
}

func (s logonState) Timeout(session *Session, e event) (nextState sessionState) {
	if e == logonTimeout {
		session.log.OnEvent("Timed out waiting for logon response")
		return latentState{}
	}

	return s
}
