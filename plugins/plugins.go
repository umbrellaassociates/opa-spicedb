package plugins

import (
	"github.com/open-policy-agent/opa/runtime"
	authzed "umbrella-associates/opa-spicedb/plugins/spicedb"
)

func Register() {
	runtime.RegisterPlugin(authzed.PluginName, authzed.Factory{})
}
