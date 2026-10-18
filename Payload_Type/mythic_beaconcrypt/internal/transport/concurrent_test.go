package transport

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	testbroker "github.com/0xd6cb6d73/mythic-beaconcrypt/internal/testsupport/broker"
	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestConcurrentRPCRegistersBeforeStartWithoutSequentialSDKHandler(t *testing.T) {
	broker, fake := testAdapter(t)
	_, err := broker.ConsumeConcurrentRPC(context.Background(), "campaign_rpc", func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.rpcs) != 0 || len(broker.concurrent) != 1 {
		t.Fatal("concurrent business queue was passed to sequential SDK listener")
	}
	broker.started = true
	if _, err := broker.ConsumeConcurrentRPC(context.Background(), "late", func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil }); err == nil {
		t.Fatal("concurrent queue registered after startup")
	}
}

// This uses real RabbitMQ delivery, correlation and confirmed replies on the
// SDK-owned connection. A campaign stalled inside its handler must not prevent
// another campaign from receiving its response through the same provider queue.
func TestConcurrentRPCOverAMQP(t *testing.T) {
	address := os.Getenv("BEACONCRYPT_AMQP_TEST_URL")
	if address == "" {
		t.Skip("set BEACONCRYPT_AMQP_TEST_URL to an isolated RabbitMQ broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	broker, err := Connect(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = broker.Close() }()
	peer, err := testbroker.Connect(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	route := "concurrent-" + uuid.NewString()
	blocked := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	_, err = broker.ConsumeConcurrentRPC(ctx, route, func(requestCtx context.Context, body []byte) ([]byte, error) {
		if token, ok := sdk.AuthTokenFromContext(requestCtx); !ok || token != "mctx_"+string(body) {
			return nil, errors.New("concurrent request lost SDK authorization header")
		}
		if string(body) == "campaign-a" {
			close(blocked)
			select {
			case <-release:
			case <-requestCtx.Done():
				return nil, requestCtx.Err()
			}
		}
		return json.Marshal(map[string]string{"campaign": string(body)})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = broker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// A second connection must not share the provider queue even though its
	// single exclusive consumer processes requests concurrently.
	probe, err := testbroker.Connect(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	_, probeErr := probe.ConsumeRPC(ctx, route, func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil })
	_ = probe.Close()
	var locked *amqp.Error
	if !errors.As(probeErr, &locked) || locked.Code != amqp.ResourceLocked {
		t.Fatalf("parallel queue lost exclusive ownership: %v", probeErr)
	}
	type callResult struct {
		body []byte
		err  error
	}
	aDone := make(chan callResult, 1)
	go func() {
		body, err := peer.Call(sdk.NewContextWithAuthToken(ctx, "mctx_campaign-a"), route, []byte("campaign-a"))
		aDone <- callResult{body, err}
	}()
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatal("blocked campaign did not start")
	}
	bDone := make(chan callResult, 1)
	go func() {
		body, err := peer.Call(sdk.NewContextWithAuthToken(ctx, "mctx_campaign-b"), route, []byte("campaign-b"))
		bDone <- callResult{body, err}
	}()
	select {
	case result := <-bDone:
		if result.err != nil || string(result.body) != `{"campaign":"campaign-b"}` {
			t.Fatalf("independent campaign response lost correlation: %s %v", result.body, result.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("independent campaign was blocked by first campaign")
	}
	select {
	case <-aDone:
		t.Fatal("first campaign unexpectedly finished before release")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case result := <-aDone:
		if result.err != nil || string(result.body) != `{"campaign":"campaign-a"}` {
			t.Fatalf("blocked campaign response lost correlation: %s %v", result.body, result.err)
		}
	case <-ctx.Done():
		broker.mu.Lock()
		terminal := broker.terminal
		broker.mu.Unlock()
		t.Fatalf("released campaign did not finish, broker terminal: %v", terminal)
	}
	select {
	case reason := <-broker.NotifyClose():
		t.Fatalf("healthy parallel replies retired worker: %v", reason)
	default:
	}
}
