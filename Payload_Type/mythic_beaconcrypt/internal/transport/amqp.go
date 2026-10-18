// Package transport adapts the MythicContainer SDK's custom queue and RPC APIs.
// The SDK owns connections, lifecycle consumers and outbound RPC correlation.
// Business RPC delivery is bounded and concurrent on the SDK-owned connection.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	sdkconfig "github.com/MythicMeta/MythicContainer/config"
	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	Exchange         = "mythic_exchange"
	MaxBodyBytes     = 192 << 20
	operationTimeout = 30 * time.Second
)

type Handler func(context.Context, []byte) ([]byte, error)
type Caller interface {
	Call(context.Context, string, []byte) ([]byte, error)
}

type sdkConnection interface {
	CloseDeadline(time.Time) error
	NotifyClose(chan *amqp.Error) chan *amqp.Error
}

type sdkHooks struct {
	initialize func()
	start      func()
	connection func() (sdkConnection, error)
	channel    func() (*amqp.Channel, error)
	addRPC     func(sdk.RPCQueueStruct)
	addDirect  func(sdk.DirectQueueStruct)
	call       func(context.Context, string, string, []byte, bool, ...sdk.RPCRetryPolicy) ([]byte, error)
	publish    func(context.Context, string, string, string, []byte, bool) error
}

// Broker is one process's SDK adapter. Register every queue before Start. The
// SDK is a process-global singleton: an adapter is never restarted or reused
// after an uncertain transport outcome. The process supervisor starts a fresh
// worker, which obtains exclusive queues before acquiring a durable owner.
type Broker struct {
	mu         sync.Mutex
	hooks      sdkHooks
	conn       sdkConnection
	started    bool
	terminal   error
	closed     chan *amqp.Error
	done       chan struct{}
	concurrent []concurrentRPC
}

var sdkProcessClaim struct {
	sync.Mutex
	claimed bool
}

func Connect(ctx context.Context, address string) (*Broker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sdkProcessClaim.Lock()
	defer sdkProcessClaim.Unlock()
	if sdkProcessClaim.claimed {
		return nil, errors.New("MythicContainer SDK permits one worker adapter per process")
	}
	if err := configureSDK(address); err != nil {
		return nil, err
	}
	sdkProcessClaim.claimed = true
	return newBroker(sdkHooks{
		initialize: sdk.Initialize,
		start:      func() { sdk.StartServices([]string{}) },
		connection: func() (sdkConnection, error) { return sdk.RabbitMQConnection.GetConnection() },
		channel: func() (*amqp.Channel, error) {
			conn, err := sdk.RabbitMQConnection.GetConnection()
			if err != nil {
				return nil, err
			}
			return conn.Channel()
		},
		addRPC:    sdk.RabbitMQConnection.AddRPCQueue,
		addDirect: sdk.RabbitMQConnection.AddDirectQueue,
		call:      sdk.RabbitMQConnection.SendRPCMessageWithContext,
		publish:   sdk.RabbitMQConnection.SendMessageWithContext,
	}), nil
}

func newBroker(hooks sdkHooks) *Broker {
	return &Broker{hooks: hooks, closed: make(chan *amqp.Error, 1), done: make(chan struct{})}
}

func configureSDK(address string) error {
	uri, err := amqp.ParseURI(address)
	if err != nil || uri.Host == "" {
		return errors.New("invalid RabbitMQ SDK address")
	}
	if uri.Scheme != "amqp" {
		return errors.New("this MythicContainer SDK supports amqp URLs only")
	}
	// SDK GetConnection interpolates these fields into a URL. Encode them once
	// so credentials and virtual hosts with reserved characters remain exact.
	credentials := strings.SplitN(url.UserPassword(uri.Username, uri.Password).String(), ":", 2)
	if len(credentials) != 2 {
		return errors.New("invalid RabbitMQ SDK credentials")
	}
	host := uri.Host
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	sdkconfig.MythicConfig.RabbitmqHost = host
	sdkconfig.MythicConfig.RabbitmqPort = uint(uri.Port)
	sdkconfig.MythicConfig.RabbitmqUser = credentials[0]
	sdkconfig.MythicConfig.RabbitmqPassword = credentials[1]
	sdkconfig.MythicConfig.RabbitmqVHost = url.PathEscape(uri.Vhost)
	sdkconfig.MythicConfig.CustomRPCTimeout = operationTimeout
	return nil
}

// Start uses the SDK's documented lower-level startup API. Custom queue
// registrations are started even with an empty built-in-services list. Unlike
// StartAndRunForever(nil), this API does not terminate for the empty list.
func (b *Broker) Start(ctx context.Context) error {
	b.mu.Lock()
	if b.terminal != nil {
		err := b.terminal
		b.mu.Unlock()
		return err
	}
	if b.started {
		b.mu.Unlock()
		return errors.New("SDK worker has already started")
	}
	b.started = true
	b.mu.Unlock()
	_, err := b.invoke(ctx, func() ([]byte, error) {
		b.hooks.initialize()
		conn, err := b.hooks.connection()
		if err != nil {
			return nil, err
		}
		b.mu.Lock()
		b.conn = conn
		terminal := b.terminal
		b.mu.Unlock()
		if terminal != nil {
			_ = conn.CloseDeadline(time.Now())
			return nil, terminal
		}
		go func() {
			if notification := <-conn.NotifyClose(make(chan *amqp.Error, 1)); notification != nil {
				b.fail(errors.New("MythicContainer SDK connection failed"))
				return
			}
			b.fail(errors.New("MythicContainer SDK connection closed"))
		}()
		b.hooks.start()
		for _, registration := range b.concurrent {
			if err := b.startConcurrentRPC(registration); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func (b *Broker) NotifyClose() <-chan *amqp.Error { return b.closed }

func (b *Broker) Close() error {
	b.fail(errors.New("MythicContainer SDK worker stopped"))
	return nil
}

func (b *Broker) fail(err error) {
	b.mu.Lock()
	if b.terminal != nil {
		b.mu.Unlock()
		return
	}
	b.terminal = err
	conn := b.conn
	close(b.done)
	b.mu.Unlock()
	b.closed <- &amqp.Error{Code: amqp.InternalError, Reason: "MythicContainer SDK worker must restart"}
	if conn != nil {
		_ = conn.CloseDeadline(time.Now())
	}
}

func (b *Broker) invoke(ctx context.Context, call func() ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	terminal := b.terminal
	b.mu.Unlock()
	if terminal != nil {
		return nil, terminal
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	type result struct {
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { body, err := call(); done <- result{body, err} }()
	select {
	case <-b.done:
		b.mu.Lock()
		err := b.terminal
		b.mu.Unlock()
		return nil, err
	case completed := <-done:
		if err := ctx.Err(); err != nil {
			b.fail(err)
			return nil, err
		}
		if completed.err != nil {
			b.fail(completed.err)
		}
		return completed.body, completed.err
	case <-ctx.Done():
		// The SDK does not observe cancellation in every connection/reply wait.
		// Never accept further protocol work while a late SDK call may complete.
		b.fail(ctx.Err())
		return nil, ctx.Err()
	}
}

func (b *Broker) Call(ctx context.Context, route string, body []byte) ([]byte, error) {
	if route == "" || len(body) == 0 || len(body) > MaxBodyBytes {
		return nil, errors.New("invalid SDK RPC request")
	}
	return b.invoke(ctx, func() ([]byte, error) {
		// The SDK may retry uncertain publish failures with these exact bytes;
		// CUSTOM_TIMEOUT disables automatic retries after a response timeout.
		return b.hooks.call(ctx, Exchange, route, body, true, sdk.RPC_RETRY_POLICY_CUSTOM_TIMEOUT)
	})
}

func (b *Broker) Publish(ctx context.Context, route string, body []byte) error {
	if route == "" || len(body) > MaxBodyBytes {
		return errors.New("invalid SDK publication")
	}
	_, err := b.invoke(ctx, func() ([]byte, error) { return nil, b.hooks.publish(ctx, Exchange, route, "", body, false) })
	return err
}

func (b *Broker) registerCheck(route string, handler Handler) error {
	if route == "" || handler == nil {
		return errors.New("invalid SDK queue registration")
	}
	if b.terminal != nil {
		return b.terminal
	}
	if b.started {
		return errors.New("register SDK queues before starting worker")
	}
	return nil
}

// ConsumeRPC registers a custom SDK RPC queue. Start must complete before
// syncing or activating the durable owner. json.RawMessage preserves the
// JSON response; returning []byte here would base64-encode it again.
func (b *Broker) ConsumeRPC(ctx context.Context, route string, handler Handler) (<-chan error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.registerCheck(route, handler); err != nil {
		return nil, err
	}
	stopped := make(chan error, 1)
	b.hooks.addRPC(sdk.RPCQueueStruct{Exchange: Exchange, Queue: route, RoutingKeyFunction: func(string) string { return route }, ContainerNameFunction: func() string { return "" }, Handler: func(requestCtx context.Context, input []byte) interface{} {
		b.mu.Lock()
		terminal := b.terminal
		b.mu.Unlock()
		if terminal != nil {
			return json.RawMessage(`{"success":false,"error":"crypto worker is unavailable"}`)
		}
		requestCtx, cancel := context.WithCancel(requestCtx)
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		defer cancel()
		body, err := handler(requestCtx, input)
		if err != nil || !json.Valid(body) || len(body) > MaxBodyBytes {
			b.fail(errors.New("SDK crypto handler failed"))
			return json.RawMessage(`{"success":false,"error":"crypto worker is unavailable"}`)
		}
		return json.RawMessage(body)
	}})
	return stopped, nil
}

func (b *Broker) ConsumeDirect(ctx context.Context, route string, handler Handler) (<-chan error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.registerCheck(route, handler); err != nil {
		return nil, err
	}
	stopped := make(chan error, 1)
	b.hooks.addDirect(sdk.DirectQueueStruct{Exchange: Exchange, Queue: route, RoutingKeyFunction: func(string) string { return route }, ContainerNameFunction: func() string { return "" }, Handler: func(requestCtx context.Context, input []byte) {
		b.mu.Lock()
		terminal := b.terminal
		b.mu.Unlock()
		if terminal != nil {
			return
		}
		requestCtx, cancel := context.WithCancel(requestCtx)
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
		defer cancel()
		if _, err := handler(requestCtx, input); err != nil {
			b.fail(errors.New("SDK lifecycle handler failed"))
		}
	}})
	return stopped, nil
}
