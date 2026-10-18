package provider

import (
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/native"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/service"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
)

// New composes protocol-specific campaign owners. Native state is provisioned
// or restored lazily by authenticated requests, never by process startup.
func New(config Config, store storage.Store) (service.Backend, error) {
	return engine.NewCampaigns(config.Engine, native.Factory{}, store)
}
