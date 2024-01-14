package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"fmt"
	"strings"
	"time"

	"github.com/zerodha/logf"
)

// NewLogger creates new instance of logger.
func NewLogger(logLevel string) *logf.Logger {
	parsedLogLevel, err := logf.LevelFromString(strings.ToLower(logLevel))
	if err != nil {
		parsedLogLevel = logf.InfoLevel
	}
	logger := logf.New(logf.Opts{
		EnableColor:     false,
		Level:           parsedLogLevel,
		EnableCaller:    false,
		TimestampFormat: fmt.Sprintf("\"%s\"", time.RFC3339),
		DefaultFields:   []any{"plugin", "JUIT Fail2Ban"},
	})

	logger.Debug(fmt.Sprintf("Setting log level to %s", strings.ToUpper(parsedLogLevel.String())), "phase", "initialize")

	return &logger
}
