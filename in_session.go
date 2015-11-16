package quickfix

import (
	"github.com/quickfixgo/quickfix/enum"
	"time"
)

type inSession struct {
}

func (state inSession) FixMsgIn(session *Session, msg Message) (nextState sessionState) {
	var msgType FIXString
	if err := msg.Header.GetField(tagMsgType, &msgType); err == nil {
		switch string(msgType) {
		//logon
		case "A":
			return state.handleLogon(session, msg)
		//logout
		case "5":
			return state.handleLogout(session, msg)
		//test request
		case "1":
			return state.handleTestRequest(session, msg)
		//resend request
		case "2":
			return state.handleResendRequest(session, msg)
		//sequence reset
		case "4":
			return state.handleSequenceReset(session, msg)
		default:
			if err := session.verify(msg); err != nil {
				return state.processReject(session, msg, err)
			}
		}
	}

	session.store.IncrNextTargetMsgSeqNum()

	return state
}

func (state inSession) Timeout(session *Session, event event) (nextState sessionState) {
	switch event {
	case needHeartbeat:
		heartBt := NewMessage()
		heartBt.Header.SetField(tagMsgType, FIXString("0"))
		session.send(heartBt)
	case peerTimeout:
		testReq := NewMessage()
		testReq.Header.SetField(tagMsgType, FIXString("1"))
		testReq.Body.SetField(tagTestReqID, FIXString("TEST"))
		session.send(testReq)
		session.peerTimer.Reset(time.Duration(int64(1.2 * float64(session.heartBeatTimeout))))
		return pendingTimeout{}
	}
	return state
}

func (state inSession) handleLogon(session *Session, msg Message) (nextState sessionState) {
	if err := session.handleLogon(msg); err != nil {
		return state.initiateLogout(session, "")
	}

	return state
}

func (state inSession) handleLogout(session *Session, msg Message) (nextState sessionState) {
	session.log.OnEvent("Received logout request")
	state.generateLogout(session)
	session.application.OnLogout(session.sessionID)

	return latentState{}
}

func (state inSession) handleSequenceReset(session *Session, msg Message) (nextState sessionState) {
	var gapFillFlag FIXBoolean
	msg.Body.GetField(tagGapFillFlag, &gapFillFlag)

	if err := session.verifySelect(msg, bool(gapFillFlag), bool(gapFillFlag)); err != nil {
		return state.processReject(session, msg, err)
	}

	var newSeqNo FIXInt
	if err := msg.Body.GetField(tagNewSeqNo, &newSeqNo); err == nil {
		expectedSeqNum := FIXInt(session.store.NextTargetMsgSeqNum())
		session.log.OnEventf("Received SequenceReset FROM: %v TO: %v", expectedSeqNum, newSeqNo)

		switch {
		case newSeqNo > expectedSeqNum:
			session.store.SetNextTargetMsgSeqNum(int(newSeqNo))
		case newSeqNo < expectedSeqNum:
			//FIXME: to be compliant with legacy tests, do not include tag in reftagid? (11c_NewSeqNoLess)
			session.doReject(msg, valueIsIncorrectNoTag())
		}
	}

	return state
}

func (state inSession) handleResendRequest(session *Session, msg Message) (nextState sessionState) {
	if err := session.verifyIgnoreSeqNumTooHighOrLow(msg); err != nil {
		return state.processReject(session, msg, err)
	}

	var err error
	var beginSeqNoField FIXInt
	if err = msg.Body.GetField(tagBeginSeqNo, &beginSeqNoField); err != nil {
		return state.processReject(session, msg, requiredTagMissing(tagBeginSeqNo))
	}

	beginSeqNo := beginSeqNoField

	var endSeqNoField FIXInt
	if err = msg.Body.GetField(tagEndSeqNo, &endSeqNoField); err != nil {
		return state.processReject(session, msg, requiredTagMissing(tagEndSeqNo))
	}

	endSeqNo := int(endSeqNoField)

	session.log.OnEventf("Received ResendRequest FROM: %d TO: %d", beginSeqNo, endSeqNo)
	expectedSeqNum := session.store.NextTargetMsgSeqNum()

	if (session.sessionID.BeginString >= enum.BeginStringFIX42 && endSeqNo == 0) ||
		(session.sessionID.BeginString <= enum.BeginStringFIX42 && endSeqNo == 999999) ||
		(endSeqNo >= expectedSeqNum) {
		endSeqNo = expectedSeqNum - 1
	}

	state.resendMessages(session, int(beginSeqNo), endSeqNo)
	session.store.IncrNextTargetMsgSeqNum()
	return state
}

func (state inSession) resendMessages(session *Session, beginSeqNo, endSeqNo int) {
	msgs := session.store.GetMessages(beginSeqNo, endSeqNo)

	seqNum := beginSeqNo
	nextSeqNum := seqNum

	var msgBytes []byte
	var ok bool
	for {
		if msgBytes, ok = <-msgs; !ok {
			//gapfill for catch-up
			if seqNum != nextSeqNum {
				state.generateSequenceReset(session, seqNum, nextSeqNum)
			}

			return
		}

		msg, _ := parseMessage(msgBytes)

		var msgType FIXString
		msg.Header.GetField(tagMsgType, &msgType)

		var sentMessageSeqNum FIXInt
		msg.Header.GetField(tagMsgSeqNum, &sentMessageSeqNum)

		if isAdminMessageType(string(msgType)) {
			nextSeqNum = int(sentMessageSeqNum) + 1
		} else {

			if seqNum != int(sentMessageSeqNum) {
				state.generateSequenceReset(session, seqNum, int(sentMessageSeqNum))
			}

			session.resend(msg)
			seqNum = int(sentMessageSeqNum) + 1
			nextSeqNum = seqNum
		}
	}
}

func (state inSession) handleTestRequest(session *Session, msg Message) (nextState sessionState) {
	if err := session.verify(msg); err != nil {
		return state.processReject(session, msg, err)
	}

	var testReq FIXString
	if err := msg.Body.GetField(tagTestReqID, &testReq); err != nil {
		session.log.OnEvent("Test Request with no testRequestID")
	} else {
		heartBt := NewMessage()
		heartBt.Header.SetField(tagMsgType, FIXString("0"))
		heartBt.Body.SetField(tagTestReqID, testReq)
		session.send(heartBt)
	}

	session.store.IncrNextTargetMsgSeqNum()

	return state
}

func (state inSession) processReject(session *Session, msg Message, rej MessageRejectError) (nextState sessionState) {
	switch TypedError := rej.(type) {
	case targetTooHigh:

		switch session.currentState.(type) {
		default:
			session.doTargetTooHigh(TypedError)
		case resendState:
			//assumes target too high reject already sent
		}
		session.messageStash[TypedError.ReceivedTarget] = msg
		return resendState{}

	case targetTooLow:
		return state.doTargetTooLow(session, msg, TypedError)
	case incorrectBeginString:
		return state.initiateLogout(session, rej.Error())
	}

	switch rej.RejectReason() {
	case rejectReasonCompIDProblem, rejectReasonSendingTimeAccuracyProblem:
		session.doReject(msg, rej)
		return state.initiateLogout(session, "")
	default:
		session.doReject(msg, rej)
		session.store.IncrNextTargetMsgSeqNum()
		return state
	}
}

func (state inSession) doTargetTooLow(session *Session, msg Message, rej targetTooLow) (nextState sessionState) {
	var posDupFlag FIXBoolean
	if err := msg.Header.GetField(tagPossDupFlag, &posDupFlag); err == nil && posDupFlag {

		origSendingTime := new(FIXUTCTimestamp)
		if err = msg.Header.GetField(tagOrigSendingTime, origSendingTime); err != nil {
			session.doReject(msg, requiredTagMissing(tagOrigSendingTime))
			return state
		}

		sendingTime := new(FIXUTCTimestamp)
		msg.Header.GetField(tagSendingTime, sendingTime)

		if sendingTime.Value.Before(origSendingTime.Value) {
			session.doReject(msg, sendingTimeAccuracyProblem())
			return state.initiateLogout(session, "")
		}

		if appReject := session.fromCallback(msg); appReject != nil {
			session.doReject(msg, appReject)
			return state.initiateLogout(session, "")
		}
	} else {
		return state.initiateLogout(session, rej.Error())
	}

	return state
}

func (state *inSession) initiateLogout(session *Session, reason string) (nextState logoutState) {
	state.generateLogoutWithReason(session, reason)
	time.AfterFunc(time.Duration(2)*time.Second, func() { session.sessionEvent <- logoutTimeout })

	return
}

func (state *inSession) generateSequenceReset(session *Session, beginSeqNo int, endSeqNo int) {
	sequenceReset := NewMessage()
	session.fillDefaultHeader(sequenceReset)

	sequenceReset.Header.SetField(tagMsgType, FIXString("4"))
	sequenceReset.Header.SetField(tagMsgSeqNum, FIXInt(beginSeqNo))
	sequenceReset.Header.SetField(tagPossDupFlag, FIXBoolean(true))
	sequenceReset.Body.SetField(tagNewSeqNo, FIXInt(endSeqNo))
	sequenceReset.Body.SetField(tagGapFillFlag, FIXBoolean(true))

	var origSendingTime FIXString
	if err := sequenceReset.Header.GetField(tagSendingTime, &origSendingTime); err == nil {
		sequenceReset.Header.SetField(tagOrigSendingTime, origSendingTime)
	}

	//FIXME error check?
	msgBytes, _ := sequenceReset.Build()
	session.sendBytes(msgBytes)
}

func (state *inSession) generateLogout(session *Session) {
	state.generateLogoutWithReason(session, "")
}

func (state *inSession) generateLogoutWithReason(session *Session, reason string) {
	reply := NewMessage()
	reply.Header.SetField(tagMsgType, FIXString("5"))
	reply.Header.SetField(tagBeginString, FIXString(session.sessionID.BeginString))
	reply.Header.SetField(tagTargetCompID, FIXString(session.sessionID.TargetCompID))
	reply.Header.SetField(tagSenderCompID, FIXString(session.sessionID.SenderCompID))

	if reason != "" {
		reply.Body.SetField(tagText, FIXString(reason))
	}

	session.send(reply)
	session.log.OnEvent("Sending logout response")
}
