package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkconfig "github.com/MythicMeta/MythicContainer/config"
	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	amqp "github.com/rabbitmq/amqp091-go"
)

type fakeConnection struct {
	closed       atomic.Int32
	closeOnce    sync.Once
	notification chan *amqp.Error
}

func (c *fakeConnection) CloseDeadline(time.Time) error {
	c.closed.Add(1)
	c.closeOnce.Do(func() { close(c.notification) })
	return nil
}
func (c *fakeConnection) NotifyClose(chan *amqp.Error) chan *amqp.Error { return c.notification }

type fakeSDK struct {
	conn    *fakeConnection
	rpcs    []sdk.RPCQueueStruct
	directs []sdk.DirectQueueStruct
	events  []string
}

func testAdapter(t *testing.T) (*Broker, *fakeSDK) {
	t.Helper()
	fake := &fakeSDK{conn: &fakeConnection{notification: make(chan *amqp.Error)}}
	broker := newBroker(sdkHooks{
		initialize: func() { fake.events = append(fake.events, "initialize") },
		connection: func() (sdkConnection, error) { fake.events = append(fake.events, "connection"); return fake.conn, nil },
		start:      func() { fake.events = append(fake.events, "start") },
		addRPC:     func(queue sdk.RPCQueueStruct) { fake.rpcs = append(fake.rpcs, queue) },
		addDirect:  func(queue sdk.DirectQueueStruct) { fake.directs = append(fake.directs, queue) },
		call: func(context.Context, string, string, []byte, bool, ...sdk.RPCRetryPolicy) ([]byte, error) {
			return []byte(`{"success":true}`), nil
		},
		publish: func(context.Context, string, string, string, []byte, bool) error { return nil },
	})
	t.Cleanup(func() { _ = broker.Close() })
	return broker, fake
}

func TestSDKCustomQueueRegistrationAndStartup(t *testing.T) {
	broker, fake := testAdapter(t)
	var directCalls int
	_, err := broker.ConsumeRPC(context.Background(), "beaconcrypt_crypto_provider_rpc", func(context.Context, []byte) ([]byte, error) {
		return []byte(`{"api_version":1,"request_id":"test-request","success":true}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.ConsumeRPC(context.Background(), "beaconcrypt_consuming_container_rpc_resync", func(context.Context, []byte) ([]byte, error) { return []byte(`{"success":true}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.ConsumeDirect(context.Background(), "beaconcrypt_container_on_start", func(context.Context, []byte) ([]byte, error) { directCalls++; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.events) != 0 {
		t.Fatal("registration started SDK before all custom queues were registered")
	}
	if err = broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fake.events, []string{"initialize", "connection", "start"}) {
		t.Fatalf("unexpected SDK startup order: %v", fake.events)
	}
	if len(fake.rpcs) != 2 || len(fake.directs) != 1 {
		t.Fatal("custom queue registrations were not passed to SDK")
	}
	for _, queue := range fake.rpcs {
		if queue.Exchange != Exchange || queue.RoutingKeyFunction(queue.ContainerNameFunction()) != queue.Queue {
			t.Fatalf("invalid SDK RPC queue: %#v", queue)
		}
	}
	response := fake.rpcs[0].Handler(context.Background(), []byte(`{}`))
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"api_version":1,"request_id":"test-request","success":true}` {
		t.Fatalf("SDK handler re-encoded JSON as bytes: %s", encoded)
	}
	fake.directs[0].Handler(context.Background(), []byte(`{}`))
	if directCalls != 1 {
		t.Fatal("SDK direct handler was not called")
	}
	if _, err = broker.ConsumeRPC(context.Background(), "late", func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil }); err == nil {
		t.Fatal("queue registered after SDK startup")
	}
}

func TestSDKCallUsesExactBytesAndNoResponseTimeoutRetry(t *testing.T) {
	broker, _ := testAdapter(t)
	input := []byte{0, 255, 128, 1}
	calls := 0
	broker.hooks.call = func(ctx context.Context, exchange, route string, body []byte, exclusive bool, policy ...sdk.RPCRetryPolicy) ([]byte, error) {
		calls++
		if token, ok := sdk.AuthTokenFromContext(ctx); !ok || token != "mctx_storage-call" {
			t.Fatal("SDK invocation lost transient authorization")
		}
		if exchange != Exchange || route != "mythic_rpc_crypto_provider_storage" || !exclusive || string(body) != string(input) || len(policy) != 1 || policy[0] != sdk.RPC_RETRY_POLICY_CUSTOM_TIMEOUT {
			t.Fatal("SDK invocation changed routing, request bytes, or retry policy")
		}
		return []byte{255, 0}, nil
	}
	ctx := sdk.NewContextWithAuthToken(context.Background(), "mctx_storage-call")
	output, err := broker.Call(ctx, "mythic_rpc_crypto_provider_storage", input)
	if err != nil || string(output) != string([]byte{255, 0}) || calls != 1 {
		t.Fatalf("SDK call changed result: %v %v calls=%d", output, err, calls)
	}
}

func TestSDKUncertainCallRetiresWorkerBeforeMoreNativeRequests(t *testing.T) {
	broker, fake := testAdapter(t)
	var processed atomic.Int32
	_, err := broker.ConsumeRPC(context.Background(), "beaconcrypt_crypto_provider_rpc", func(context.Context, []byte) ([]byte, error) { processed.Add(1); return []byte(`{}`), nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	finished := make(chan struct{})
	var calls atomic.Int32
	broker.hooks.call = func(context.Context, string, string, []byte, bool, ...sdk.RPCRetryPolicy) ([]byte, error) {
		calls.Add(1)
		<-release
		close(finished)
		return []byte(`{"late":true}`), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = broker.Call(ctx, "storage", []byte(`{}`))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncertain SDK call did not respect caller deadline: %v", err)
	}
	select {
	case reason := <-broker.NotifyClose():
		if reason == nil {
			t.Fatal("missing SDK worker retirement reason")
		}
	case <-time.After(time.Second):
		t.Fatal("uncertain SDK call did not signal worker restart")
	}
	if fake.conn.closed.Load() != 1 {
		t.Fatal("uncertain SDK call left captured connection alive")
	}
	if _, err = broker.Call(context.Background(), "storage", []byte(`{}`)); err == nil || calls.Load() != 1 {
		t.Fatal("terminal adapter accepted more SDK work")
	}
	result := fake.rpcs[0].Handler(context.Background(), []byte(`{}`))
	if processed.Load() != 0 {
		t.Fatal("terminal adapter accepted native request")
	}
	if _, ok := result.(json.RawMessage); !ok {
		t.Fatal("terminal rejection is not raw JSON")
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late SDK call did not finish")
	}
}

func TestSDKConnectionLossRetiresWorker(t *testing.T) {
	broker, fake := testAdapter(t)
	if err := broker.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.conn.closeOnce.Do(func() { close(fake.conn.notification) })
	select {
	case reason := <-broker.NotifyClose():
		if reason == nil {
			t.Fatal("missing SDK connection loss reason")
		}
	case <-time.After(time.Second):
		t.Fatal("SDK connection loss did not retire worker")
	}
	if _, err := broker.Call(context.Background(), "storage", []byte(`{}`)); err == nil {
		t.Fatal("adapter resumed work after SDK connection loss")
	}
}

func TestSDKLateConnectionCannotStartNativeWorkerAfterDeadline(t *testing.T) {
	broker, fake := testAdapter(t)
	release := make(chan struct{})
	finished := make(chan struct{})
	broker.hooks.initialize = func() { <-release }
	broker.hooks.connection = func() (sdkConnection, error) { defer close(finished); return fake.conn, nil }
	var started atomic.Bool
	broker.hooks.start = func() { started.Store(true) }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := broker.Start(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unbounded SDK startup: %v", err)
	}
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("late SDK initialization did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for fake.conn.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fake.conn.closed.Load() == 0 || started.Load() {
		t.Fatal("late SDK connection started worker after terminal startup deadline")
	}
}

func TestSDKConfigurationPreservesReservedCredentialsAndIPv6(t *testing.T) {
	previous := sdkconfig.MythicConfig
	t.Cleanup(func() { sdkconfig.MythicConfig = previous })
	original := "amqp://provider%40mythic:p%40ss%3A%2F%3F%23%25word@[::1]:5673/test%20space%2Fvhost"
	if err := configureSDK(original); err != nil {
		t.Fatal(err)
	}
	config := sdkconfig.MythicConfig
	reconstructed := fmt.Sprintf("amqp://%s:%s@%s:%d/%s", config.RabbitmqUser, config.RabbitmqPassword, config.RabbitmqHost, config.RabbitmqPort, config.RabbitmqVHost)
	parsed, err := amqp.ParseURI(reconstructed)
	if err != nil {
		t.Fatal(err)
	}
	want, err := amqp.ParseURI(original)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, want) || config.CustomRPCTimeout != operationTimeout {
		t.Fatal("SDK URL interpolation changed broker credentials, address, or virtual host")
	}
	if err := configureSDK("amqps://user:password@host/vhost"); err == nil {
		t.Fatal("SDK silently downgraded unsupported TLS URL")
	}
}

func TestSDKPreCancelledCallDoesNotRetireOrInvokeWorker(t *testing.T) {
	broker, fake := testAdapter(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := broker.Call(ctx, "storage", []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if fake.conn.closed.Load() != 0 {
		t.Fatal("pre-cancelled call retired an unused connection")
	}
	if _, err := broker.Call(context.Background(), "storage", []byte(`{}`)); err != nil {
		t.Fatal("pre-cancelled call poisoned adapter")
	}
}
