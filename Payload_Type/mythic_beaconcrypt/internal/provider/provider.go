// Package provider is the replaceable part of this example. Add your protocol,
// configuration and state management here; keep the Mythic adapter separate.
package provider

import (
	"context"
	"encoding/json"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/service"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

type Config struct {
	Service service.Config
}

func LoadConfig() (Config, error) {
	config, err := service.LoadConfig("beaconcrypt", "BEACONCRYPT")
	if err != nil {
		return Config{}, err
	}
	config.Description = "Crypto provider skeleton; protocol methods are not implemented"
	config.Version = "0.0.1"
	config.Capabilities = wire.Capabilities{
		APIVersion: wire.APIVersion, Schemes: []string{"example"}, Establishment: "single_round",
		SessionPersistence: "volatile", MaxMessageBytes: 1 << 20, ResultRetentionSeconds: 60,
	}
	return Config{Service: config}, nil
}

type Provider struct {
	capabilities wire.Capabilities
}

// New receives Mythic's authenticated opaque state store. This skeleton does
// not use it: construction and describe must not create campaign state. A real
// durable provider can retain it and use each request's context for storage RPC.
func New(config Config, _ storage.Store) (service.Backend, error) {
	if err := config.Service.Capabilities.Validate(); err != nil {
		return nil, err
	}
	return &Provider{capabilities: config.Service.Capabilities}, nil
}

func (p *Provider) Close() {}

func (p *Provider) Handle(_ context.Context, request wire.Request) wire.Response {
	response := wire.Response{
		APIVersion: wire.APIVersion, RequestID: request.RequestID,
		OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext,
	}
	if err := request.Validate(); err != nil {
		response.Error = &wire.Failure{Code: "invalid_input", Message: err.Error(), Outcome: wire.OutcomeRejected}
		return response
	}
	switch request.Method {
	case wire.Describe:
		response.Success = true
		response.ProviderJSON, _ = json.Marshal(p.capabilities)
		return response
	case wire.PrepareProfile:
		// TODO: Validate scheme and provider_json. Return profile_ref and opaque
		// agent_config; bind the profile to operation_scope_id. Persist the exact
		// result by request_id and reject the same ID with a different digest.
	case wire.BeginSession:
		// TODO: Authenticate the initial message and payload_uuid/next_uuid
		// claims against this operation's profile. Return session_ref, namespace,
		// optional state_id, and the nonempty establishment reply in message.
		// Commit state and the exact result before acknowledging establishment.
	case wire.Open:
		// TODO: Verify session ownership, scope and revocation before opening the
		// authenticated packet. Return plaintext in message. Cache the result
		// with the state transition so retries do not advance receive state twice.
	case wire.Seal:
		// TODO: Verify session ownership, scope and revocation before sealing.
		// Return ciphertext in message and atomically record state plus result;
		// repeating request_id must return the same bytes without new encryption.
	case wire.GetOperation:
		// TODO: Find lookup_request_id within this operation and authorized
		// session. Return its recorded outcome, replacing only request_id and
		// auth_context with this lookup request's values. Unknown stays unresolved.
	case wire.RevokeSession:
		// TODO: Verify scope and ownership, then atomically record revocation and
		// its exact result. Reject further open/seal calls, including old requests
		// replayed after revocation; repeated revocation must remain safe.
	}
	// Every unfinished method rejects before changing any cryptographic state.
	response.Error = &wire.Failure{
		Code: "not_implemented", Message: "implement this protocol method in internal/provider",
		Outcome: wire.OutcomeRejected,
	}
	return response
}
