package core

import (
	"fmt"
	stdLog "log"
)

type logLevelT int

const (
	logError logLevelT = iota
	logInfo
	logDebug
)

var logLevel = logInfo

type logger interface {
	Infof(string, ...interface{})
	Errorf(string, ...interface{})
	Debugf(string, ...interface{})
}

type levelLoggerT struct{}

var log logger = &levelLoggerT{}

var errorLog, infoLog *stdLog.Logger

func LogInit() {
	errorLog = stdLog.New(stdLog.Writer(), stdLog.Prefix()+"[ERR] ", stdLog.Flags())
	infoLog = stdLog.New(stdLog.Writer(), stdLog.Prefix()+"[INF] ", stdLog.Flags())
	stdLog.SetPrefix(stdLog.Prefix() + "[DBG] ")
}

func (l *levelLoggerT) Errorf(s string, v ...interface{}) {
	if logLevel >= logError {
		_ = errorLog.Output(2, fmt.Sprintf("[ERR] "+s, v...))
	}
}

func (l *levelLoggerT) Infof(s string, v ...interface{}) {
	if logLevel >= logInfo {
		_ = infoLog.Output(2, fmt.Sprintf(s, v...))
	}
}

func (l *levelLoggerT) Debugf(s string, v ...interface{}) {
	if logLevel >= logDebug {
		_ = stdLog.Output(2, fmt.Sprintf(s, v...))
	}
}
