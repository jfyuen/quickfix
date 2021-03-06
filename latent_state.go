package quickfix

type latentState struct{}

func (state latentState) FixMsgIn(session *Session, msg Message) (nextState sessionState) {
	session.log.OnEventf("Invalid Session State: Unexpected Msg %v while in Latent state", msg)
	return state
}

func (state latentState) Timeout(*Session, event) (nextState sessionState) {
	return state
}
