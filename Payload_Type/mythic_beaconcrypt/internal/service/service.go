// Package service adapts MythicContainer v4 lifecycle messages to the generic
// crypto-provider API. Protocol implementation and state ownership belong to
// the provider backend.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/transport"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
)

const (
	ContainerVersion = "v1.5.0"
	SyncRoute        = "consuming_container_sync"
)

type Processor interface {
	Handle(context.Context, wire.Request) wire.Response
}

// Backend owns protocol processing and its shutdown. Factories compose a
// backend without storage IO; state is loaded lazily under request authorization.
type Backend interface {
	Processor
	Close()
}

type Factory func(storage.Store) (Backend, error)

func syncMessage(config Config) ([]byte, error) {
	if _, err := wire.RoutingKey(config.Name); err != nil {
		return nil, err
	}
	if err := config.Capabilities.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"container_version": ContainerVersion,
		"consuming_container": map[string]any{
			"name": config.Name, "type": "crypto", "description": config.Description, "semver": config.Version,
			"subscriptions": []string{}, "crypto_capabilities": config.Capabilities,
		},
	})
}

func Sync(ctx context.Context, caller transport.Caller, config Config) error {
	body, err := syncMessage(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, config.RPCTimeout)
	defer cancel()
	reply, err := caller.Call(ctx, SyncRoute, body)
	if err != nil {
		return errors.New("mythic consuming-service sync failed")
	}
	var response struct {
		Success bool `json:"success"`
	}
	if json.Unmarshal(reply, &response) != nil || !response.Success {
		return errors.New("mythic rejected consuming-service sync")
	}
	return nil
}

// NewHandler accepts ordinary Mythic JSON RPC with the SDK's transient
// authorization context. Storage calls inherit that same context; no service
// credential or startup token is retained.
func NewHandler(processor Processor, timeout time.Duration) transport.Handler {
	return func(ctx context.Context, body []byte) ([]byte, error) {
		if len(body) > transport.MaxBodyBytes {
			return []byte(`{"success":false,"error":"crypto provider request exceeds limit"}`), nil
		}
		var request wire.Request
		if json.Unmarshal(body, &request) != nil {
			return []byte(`{"success":false,"error":"invalid crypto provider request"}`), nil
		}
		token, ok := sdk.AuthTokenFromContext(ctx)
		if !ok || token == "" || request.AuthContext != token {
			return []byte(`{"success":false,"error":"invalid crypto provider authorization context"}`), nil
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return json.Marshal(processor.Handle(ctx, request))
	}
}

// Run acquires broker exclusivity before accepting protocol requests. Provider
// state is created or restored lazily by authenticated requests. A broker loss
// ends this process instance; its supervisor starts a fresh worker.
func Run(ctx context.Context, config Config, factory Factory) error {
	if factory == nil {
		return errors.New("crypto provider backend factory is required")
	}
	if _, err := syncMessage(config); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	connectCtx, connectCancel := context.WithTimeout(ctx, config.RPCTimeout)
	broker, err := transport.Connect(connectCtx, config.AMQPURL)
	connectCancel()
	if err != nil {
		return errors.New("cannot connect to RabbitMQ")
	}
	defer func() { _ = broker.Close() }()
	store, err := storage.New(broker, config.Name)
	if err != nil {
		return err
	}
	processor, err := factory(store)
	if err != nil {
		return err
	}
	if processor == nil {
		return errors.New("crypto provider backend is required")
	}
	defer func() {
		cancel()
		processor.Close()
	}()
	ready := make(chan struct{})
	route, err := wire.RoutingKey(config.Name)
	if err != nil {
		return err
	}
	providerHandler := NewHandler(processor, config.RPCTimeout)
	cryptoErrors, err := broker.ConsumeConcurrentRPC(ctx, route, func(ctx context.Context, body []byte) ([]byte, error) {
		select {
		case <-ready:
			return providerHandler(ctx, body)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err != nil {
		return errors.New("cannot acquire exclusive provider queue")
	}
	resyncErrors, err := broker.ConsumeRPC(ctx, config.Name+"_consuming_container_rpc_resync", func(ctx context.Context, _ []byte) ([]byte, error) {
		err := Sync(ctx, broker, config)
		return json.Marshal(map[string]any{"success": err == nil})
	})
	if err != nil {
		return errors.New("cannot start provider resync queue")
	}
	startErrors, err := broker.ConsumeDirect(ctx, config.Name+"_container_on_start", func(_ context.Context, _ []byte) ([]byte, error) {
		// The operator token in this notification is intentionally not retained.
		// Each business request supplies its own transient Mythic authorization.
		return nil, nil
	})
	if err != nil {
		return errors.New("cannot start provider lifecycle queue")
	}
	startCtx, startCancel := context.WithTimeout(ctx, config.RPCTimeout)
	err = broker.Start(startCtx)
	startCancel()
	if err != nil {
		return errors.New("cannot start MythicContainer provider listeners")
	}
	if err = Sync(ctx, broker, config); err != nil {
		return err
	}
	close(ready)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case brokerErr := <-broker.NotifyClose():
		if brokerErr != nil {
			return errors.New("rabbitmq connection failed")
		}
		return errors.New("rabbitmq connection closed")
	case consumerErr := <-cryptoErrors:
		if consumerErr != nil {
			return errors.New("crypto request consumer failed")
		}
		return errors.New("crypto request consumer stopped")
	case consumerErr := <-resyncErrors:
		if consumerErr != nil {
			return errors.New("provider resync consumer failed")
		}
		return errors.New("provider resync consumer stopped")
	case consumerErr := <-startErrors:
		if consumerErr != nil {
			return errors.New("provider lifecycle consumer failed")
		}
		return errors.New("provider lifecycle consumer stopped")
	}
}
