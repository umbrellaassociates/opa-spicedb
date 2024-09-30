package spicedb

import (
	"context"
	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"github.com/open-policy-agent/opa/plugins"
	"github.com/open-policy-agent/opa/util"
	"google.golang.org/grpc"
	"sync"
)

const PluginName = "spicedb"

type Config struct {
	Endpoint string `json:"endpoint"`
	Insecure bool   `json:"insecure"`
	Token    string `json:"token"`
	Schemaprefix    string `json:"schemaprefix"`
}

type SpicedbPlugin struct {
	manager *plugins.Manager
	mtx     sync.Mutex
	config  Config
	client  *authzed.Client
}

var instance *SpicedbPlugin = nil
var Schemaprefix string = ""

func GetAuthzedClient() *authzed.Client {

	if instance == nil {
		return nil
	}

	instance.mtx.Lock()
	defer instance.mtx.Unlock()

	return instance.client
}

func (p *SpicedbPlugin) Start(ctx context.Context) error {

	grpcSecurity, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
	if p.config.Insecure {
		grpcSecurity = grpc.WithInsecure()
	}
	
	if p.config.Schemaprefix != "" {
		Schemaprefix = p.config.Schemaprefix
	}

	client, err := authzed.NewClient(
		p.config.Endpoint,
		// grpcutil.WithSystemCerts(grpcutil.VerifyCA),
		grpcSecurity,
		grpcutil.WithInsecureBearerToken(p.config.Token),
	)

	p.client = client

	// Expose plugin instance in global to be able to access the authzed client from the custom builtins
	instance = p

	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateOK})

	return err

}

func (p *SpicedbPlugin) Stop(ctx context.Context) {
	p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})
}

func (p *SpicedbPlugin) Reconfigure(ctx context.Context, config any) {
	// Todo: Lock schemaprefix
	p.mtx.Lock()
	defer p.mtx.Unlock()

	if p.config.Endpoint != config.(Config).Endpoint {
		p.Stop(ctx)
		if err := p.Start(ctx); err != nil {
			p.manager.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateErr})
		}
	}
	p.config = config.(Config)
}

type Factory struct{}

func (Factory) New(m *plugins.Manager, config any) plugins.Plugin {

	m.UpdatePluginStatus(PluginName, &plugins.Status{State: plugins.StateNotReady})

	return &SpicedbPlugin{
		manager: m,
		config:  config.(Config),
	}
}

func (Factory) Validate(_ *plugins.Manager, config []byte) (any, error) {
	parsedConfig := Config{}
	err := util.Unmarshal(config, &parsedConfig)
	return parsedConfig, err
}
