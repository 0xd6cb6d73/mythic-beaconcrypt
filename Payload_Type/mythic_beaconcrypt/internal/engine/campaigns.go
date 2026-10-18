package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

const campaignStateSuffix = "/campaign/"

// Campaigns routes authenticated Mythic operation scopes to independent durable
// owners. Each owner has its own native identity, ratchets, metadata and mutex.
// The map lock only protects owner discovery; storage and native work never run
// under it. Callers must authenticate the request before invoking Handle.
type Campaigns struct {
	mu      sync.Mutex
	config  Config
	factory Factory
	store   Store
	owners  map[int]*Engine
	closed  bool
}

func NewCampaigns(config Config, factory Factory, store Store) (*Campaigns, error) {
	// Campaigns are provisioned by PrepareProfile, never by process startup.
	config.Initialize = false
	prototype, err := New(config, factory, store)
	if err != nil {
		return nil, err
	}
	config = prototype.config
	// Reserve enough space for every positive int64 Mythic operation ID. This
	// also keeps the same configured prefix valid across 32- and 64-bit builds.
	if len(config.StateID)+len(campaignStateSuffix)+len("9223372036854775807") > wire.MaxStateIDBytes {
		return nil, errors.New("state identifier prefix is too long for campaign keys")
	}
	return &Campaigns{config: config, factory: factory, store: store, owners: make(map[int]*Engine)}, nil
}

func (c *Campaigns) Capabilities() wire.Capabilities {
	return (&Engine{config: c.config}).Capabilities()
}

func (c *Campaigns) stateID(operationID int) string {
	return c.config.StateID + campaignStateSuffix + strconv.Itoa(operationID)
}

func (c *Campaigns) Handle(ctx context.Context, request wire.Request) wire.Response {
	if err := request.Validate(); err != nil {
		return failure(request, "invalid_input", err.Error(), "rejected")
	}
	if len(request.Message) > c.config.MaxMessageBytes {
		return failure(request, "invalid_input", "provider message exceeds configured limit", "rejected")
	}
	if request.Scheme != "" && request.Scheme != Scheme {
		return failure(request, "invalid_input", "unsupported cryptographic scheme", "rejected")
	}
	stateID := c.stateID(request.OperationScopeID)
	if request.Namespace != "" && request.Namespace != c.config.Namespace || request.StateID != "" && request.StateID != stateID {
		return failure(request, "unavailable_session", "state scope does not match this campaign", "rejected")
	}
	if request.Method == wire.PrepareProfile {
		// Reject malformed profiles before a request can provision an identity.
		var config map[string]json.RawMessage
		if request.Scheme != Scheme || len(request.ProviderJSON) > 0 && (json.Unmarshal(request.ProviderJSON, &config) != nil || len(config) != 0) {
			return failure(request, "invalid_input", "unsupported profile configuration", "rejected")
		}
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return failure(request, "owner_unavailable", "provider is closed", "unresolved")
	}
	if request.Method == wire.Describe {
		c.mu.Unlock()
		response := reply(request)
		response.ProviderJSON, _ = json.Marshal(c.Capabilities())
		return response
	}
	owner := c.owners[request.OperationScopeID]
	if owner == nil {
		config := c.config
		config.StateID = stateID
		// New only validates configuration; it performs no storage or native IO.
		var err error
		owner, err = New(config, c.factory, c.store)
		if err != nil {
			c.mu.Unlock()
			return failure(request, "owner_unavailable", "campaign owner cannot be configured", "unresolved")
		}
		owner.campaignID = request.OperationScopeID
		c.owners[request.OperationScopeID] = owner
	}
	c.mu.Unlock()
	return owner.Handle(ctx, request)
}

func (c *Campaigns) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	owners := make([]*Engine, 0, len(c.owners))
	for _, owner := range c.owners {
		owners = append(owners, owner)
	}
	c.mu.Unlock()
	for _, owner := range owners {
		owner.Close()
	}
}
