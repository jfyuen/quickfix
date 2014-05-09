package quickfix

import (
	"bufio"
	"fmt"
	"github.com/quickfixgo/quickfix/config"
	"io"
	"regexp"
)

//The Settings type represents a collection of global and session settings.
type Settings struct {
	globalSettings  *SessionSettings
	sessionSettings map[SessionID]*SessionSettings
}

//Init initializes or resets a Settings instance
func (s *Settings) Init() {
	s.globalSettings = NewSessionSettings()
	s.sessionSettings = make(map[SessionID]*SessionSettings)
}

func (s *Settings) lazyInit() {
	if s.globalSettings == nil {
		s.Init()
	}
}

//NewSettings creates a Settings instance
func NewSettings() *Settings {
	s := &Settings{}
	s.Init()
	return s
}

func sessionIDFromSessionSettings(globalSettings *SessionSettings, sessionSettings *SessionSettings) SessionID {
	sessionID := SessionID{}

	for _, settings := range []*SessionSettings{globalSettings, sessionSettings} {
		if settings.HasSetting(config.BeginString) {
			sessionID.BeginString, _ = settings.Setting(config.BeginString)
		}

		if settings.HasSetting(config.TargetCompID) {
			sessionID.TargetCompID, _ = settings.Setting(config.TargetCompID)
		}

		if settings.HasSetting(config.SenderCompID) {
			sessionID.SenderCompID, _ = settings.Setting(config.SenderCompID)
		}

		if settings.HasSetting(config.SessionQualifier) {
			sessionID.Qualifier, _ = settings.Setting(config.SessionQualifier)
		}
	}

	return sessionID
}

//ParseSettings creates and initializes a Settings instance with config parsed from a Reader.
//Returns error if the config is has parse errors
func ParseSettings(reader io.Reader) (*Settings, error) {
	s := NewSettings()

	scanner := bufio.NewScanner(reader)
	blankRegEx := regexp.MustCompile(`^\s*$`)
	commentRegEx := regexp.MustCompile(`^#.*`)
	defaultRegEx := regexp.MustCompile(`^\[DEFAULT\]\s*$`)
	sessionRegEx := regexp.MustCompile(`^\[SESSION\]\s*$`)
	settingRegEx := regexp.MustCompile(`^(.*)=(.*)$`)

	var settings *SessionSettings

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		switch {
		case commentRegEx.MatchString(line) || blankRegEx.MatchString(line):
			continue

		case defaultRegEx.MatchString(line):
			settings = s.GlobalSettings()

		case sessionRegEx.MatchString(line):
			if settings != nil && settings != s.GlobalSettings() {
				if _, err := s.AddSession(settings); err != nil {
					return nil, err
				}
			}
			settings = NewSessionSettings()

		case settingRegEx.MatchString(line):
			parts := settingRegEx.FindStringSubmatch(line)
			settings.Set(parts[1], parts[2])

		default:
			return s, fmt.Errorf("error parsing line %v", lineNumber)
		}
	}

	if err := scanner.Err(); err != nil {
		return s, err
	}

	if settings == nil || settings == s.GlobalSettings() {
		return s, fmt.Errorf("no sessions declared")
	}
	_, err := s.AddSession(settings)

	return s, err
}

//GlobalSettings are default setting inherited by all session settings.
func (s *Settings) GlobalSettings() *SessionSettings {
	s.lazyInit()
	return s.globalSettings
}

//SessionSettings return all session settings overlaying globalsettings.
func (s *Settings) SessionSettings() map[SessionID]*SessionSettings {
	allSessionSettings := make(map[SessionID]*SessionSettings)

	for sessionID, settings := range s.sessionSettings {
		cloneSettings := s.globalSettings.clone()
		cloneSettings.overlay(settings)
		allSessionSettings[sessionID] = cloneSettings
	}

	return allSessionSettings
}

//AddSession adds Session Settings to Settings instance. Returns an error if session settings with duplicate sessionID has already been added
func (s *Settings) AddSession(sessionSettings *SessionSettings) (SessionID, error) {
	s.lazyInit()

	sessionID := sessionIDFromSessionSettings(s.GlobalSettings(), sessionSettings)
	if _, dup := s.sessionSettings[sessionID]; dup {
		return sessionID, fmt.Errorf("duplicate session configured for %v", sessionID)
	}

	s.sessionSettings[sessionID] = sessionSettings

	return sessionID, nil
}
