package plugins

import (
	"github.com/open-policy-agent/opa/runtime"
	authzed "github.com/umbrellaassociates/opa-spicedb/plugins/spicedb"
)

func Register() {
	runtime.RegisterPlugin(authzed.PluginName, authzed.Factory{})
}
