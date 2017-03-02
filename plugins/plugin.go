package plugins

import (
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("check/plugin")

type Plugin interface {
	// Gather(domain string) (Result, error)
	Name() string

	Check(domain string) <-chan Issue
}

type OptionFn func(interface{})

type Severity string

const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
	SeverityInfo    Severity = "INFO"
	SeverityDebug   Severity = "DEBUG"
	SeverityOK      Severity = "OK"
)

type Issue struct {
	Severity Severity
	Message  string
}

var Plugins []PluginFn = []PluginFn{}

type PluginFn func(...OptionFn) Plugin

func Register(p PluginFn) PluginFn {
	Plugins = append(Plugins, p)
	return p
}
