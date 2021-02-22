package log

import (
	"fmt"
	stdLog "log"
	"os"
	"p11nethsm/config"
)

type logLevelT int

const (
	logError logLevelT = iota
	logInfo
	logDebug
)

var logLevel = logInfo

var errorLog, infoLog *stdLog.Logger

func init() {
	conf := config.Get()
	logPath := conf.LogFile
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			stdLog.Printf("cannot create logfile at given path: %s", err)
		} else {
			stdLog.SetOutput(logFile)
		}
	} else {
		stdLog.SetPrefix("[p11nethsm] ")
	}
	if conf.Debug {
		logLevel = logDebug
		stdLog.SetPrefix("=== " + stdLog.Prefix())
		stdLog.SetFlags(stdLog.Flags() | stdLog.Lshortfile | stdLog.Lmicroseconds)
	}
	errorLog = stdLog.New(stdLog.Writer(), stdLog.Prefix()+"[ERR] ", stdLog.Flags())
	infoLog = stdLog.New(stdLog.Writer(), stdLog.Prefix()+"[INF] ", stdLog.Flags())
	stdLog.SetPrefix(stdLog.Prefix() + "[DBG] ")
}

func Errorf(s string, v ...interface{}) {
	if logLevel >= logError {
		_ = errorLog.Output(2, fmt.Sprintf(s, v...))
	}
}

func Infof(s string, v ...interface{}) {
	if logLevel >= logInfo {
		_ = infoLog.Output(2, fmt.Sprintf(s, v...))
	}
}

func Debugf(s string, v ...interface{}) {
	if logLevel >= logDebug {
		_ = stdLog.Output(2, fmt.Sprintf(s, v...))
	}
}
