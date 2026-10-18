// Package broker provides a raw AMQP Mythic peer only for integration tests.
// Production provider code uses the MythicContainer SDK adapter.
package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/google/uuid"
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

// Broker owns one connection. Calls never retry automatically. A context
// deadline aborts the connection, interrupting the AMQP library's synchronous
// setup and publish methods as well as its reply wait. Reconnect at the service
// boundary and reconcile an uncertain operation through durable storage.
type Broker struct{ conn *amqp.Connection }

func Connect(ctx context.Context, address string) (*Broker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var stop func() bool
	var raw net.Conn
	conn, err := amqp.DialConfig(address, amqp.Config{
		Heartbeat: 10 * time.Second,
		Dial: func(network, address string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			raw = c
			if deadline, ok := ctx.Deadline(); ok {
				_ = c.SetDeadline(deadline)
			}
			stop = context.AfterFunc(ctx, func() { _ = c.Close() })
			return c, nil
		},
	})
	if stop != nil {
		stop()
	}
	if err != nil {
		return nil, fmt.Errorf("connect to AMQP: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = conn.CloseDeadline(time.Now())
		return nil, err
	}
	if raw != nil {
		_ = raw.SetDeadline(time.Time{})
	}
	return &Broker{conn: conn}, nil
}

func (b *Broker) Close() error { return b.conn.CloseDeadline(time.Now().Add(time.Second)) }

func (b *Broker) NotifyClose() <-chan *amqp.Error {
	return b.conn.NotifyClose(make(chan *amqp.Error, 1))
}

func (b *Broker) operation(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	stop := context.AfterFunc(ctx, func() { _ = b.conn.CloseDeadline(time.Now()) })
	return ctx, func() { stop(); cancel() }
}

func declareExchange(ch *amqp.Channel) error {
	return ch.ExchangeDeclare(Exchange, "direct", true, true, false, false, nil)
}

func (b *Broker) Call(ctx context.Context, route string, body []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if route == "" || len(body) == 0 || len(body) > MaxBodyBytes {
		return nil, errors.New("invalid AMQP RPC request")
	}
	ctx, done := b.operation(ctx)
	defer done()
	ch, err := b.conn.Channel()
	if err != nil {
		return nil, err
	}
	defer func() { _ = ch.Close() }()
	if err = declareExchange(ch); err != nil {
		return nil, err
	}
	replies, err := ch.Consume("amq.rabbitmq.reply-to", "", true, true, false, false, nil)
	if err != nil {
		return nil, err
	}
	correlationID := uuid.NewString()
	publisher, err := newPublisher(ch)
	if err != nil {
		return nil, err
	}
	if err = publisher.publish(ctx, Exchange, route, true, amqp.Publishing{
		Headers: sdk.HeadersFromContext(ctx), ContentType: "application/json", Body: body, CorrelationId: correlationID, ReplyTo: "amq.rabbitmq.reply-to",
	}); err != nil {
		return nil, err
	}
	for {
		select {
		case reply, ok := <-replies:
			if !ok {
				return nil, errors.New("AMQP RPC reply consumer stopped")
			}
			if reply.CorrelationId != correlationID {
				continue
			}
			if len(reply.Body) > MaxBodyBytes {
				return nil, errors.New("AMQP RPC response exceeds limit")
			}
			return reply.Body, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (b *Broker) Publish(ctx context.Context, route string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if route == "" || len(body) > MaxBodyBytes {
		return errors.New("invalid AMQP publication")
	}
	ctx, done := b.operation(ctx)
	defer done()
	ch, err := b.conn.Channel()
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()
	if err = declareExchange(ch); err != nil {
		return err
	}
	publisher, err := newPublisher(ch)
	if err != nil {
		return err
	}
	return publisher.publish(ctx, Exchange, route, true, amqp.Publishing{Headers: sdk.HeadersFromContext(ctx), ContentType: "application/json", Body: body})
}

type publisher struct {
	ch       *amqp.Channel
	confirm  <-chan amqp.Confirmation
	returned <-chan amqp.Return
}

func newPublisher(ch *amqp.Channel) (*publisher, error) {
	if err := ch.Confirm(false); err != nil {
		return nil, err
	}
	return &publisher{ch: ch, confirm: ch.NotifyPublish(make(chan amqp.Confirmation, 1)), returned: ch.NotifyReturn(make(chan amqp.Return, 1))}, nil
}

func (p *publisher) publish(ctx context.Context, exchange, route string, mandatory bool, message amqp.Publishing) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.ch.Publish(exchange, route, mandatory, false, message); err != nil {
		return err
	}
	select {
	case ret := <-p.returned:
		return fmt.Errorf("AMQP publication rejected: %d %s", ret.ReplyCode, ret.ReplyText)
	case ack, ok := <-p.confirm:
		if !ok || !ack.Ack {
			return errors.New("AMQP publication was not confirmed")
		}
		select {
		case ret := <-p.returned:
			return fmt.Errorf("AMQP publication rejected: %d %s", ret.ReplyCode, ret.ReplyText)
		default:
			return nil
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ConsumeRPC binds the exclusive named queue used by Mythic's container health
// check before returning. A reply is confirmed before acknowledging its input.
// On connection loss Mythic retries the immutable request; a delivery
// tag is never reused on a replacement channel.
func (b *Broker) ConsumeRPC(ctx context.Context, route string, handler Handler) (<-chan error, error) {
	return b.consume(ctx, route, handler, true)
}

func (b *Broker) ConsumeDirect(ctx context.Context, route string, handler Handler) (<-chan error, error) {
	return b.consume(ctx, route, handler, false)
}

func (b *Broker) consume(ctx context.Context, route string, handler Handler, rpc bool) (<-chan error, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if route == "" || handler == nil {
		return nil, errors.New("invalid AMQP consumer")
	}
	setup, done := b.operation(ctx)
	ch, err := b.conn.Channel()
	if err != nil {
		done()
		return nil, err
	}
	fail := func(err error) (<-chan error, error) { _ = ch.Close(); done(); return nil, err }
	if err = declareExchange(ch); err != nil {
		return fail(err)
	}
	if _, err = ch.QueueDeclare(route, rpc, true, true, false, nil); err != nil {
		return fail(err)
	}
	if err = ch.QueueBind(route, route, Exchange, false, nil); err != nil {
		return fail(err)
	}
	if err = ch.Qos(1, 0, false); err != nil {
		return fail(err)
	}
	deliveries, err := ch.Consume(route, "", false, true, false, false, nil)
	if err != nil {
		return fail(err)
	}
	var publisher *publisher
	if rpc {
		publisher, err = newPublisher(ch)
		if err != nil {
			return fail(err)
		}
	}
	if err = setup.Err(); err != nil {
		return fail(err)
	}
	done()
	result := make(chan error, 1)
	go func() {
		stop := context.AfterFunc(ctx, func() { _ = b.conn.CloseDeadline(time.Now()) })
		defer stop()
		defer close(result)
		defer func() { _ = b.conn.CloseDeadline(time.Now()); _ = ch.Close() }()
		for {
			select {
			case <-ctx.Done():
				result <- ctx.Err()
				return
			case delivery, ok := <-deliveries:
				if !ok {
					result <- errors.New("AMQP consumer stopped")
					return
				}
				if len(delivery.Body) > MaxBodyBytes || (rpc && delivery.ReplyTo == "") {
					if err := delivery.Reject(false); err != nil {
						result <- err
						return
					}
					continue
				}
				requestCtx := ctx
				if token, ok := sdk.AuthTokenFromHeaders(delivery.Headers); ok {
					requestCtx = sdk.NewContextWithAuthToken(ctx, token)
				}
				response, err := handler(requestCtx, delivery.Body)
				if err != nil {
					result <- err
					return
				}
				if rpc {
					if len(response) == 0 || len(response) > MaxBodyBytes {
						result <- errors.New("invalid AMQP handler response")
						return
					}
					op, finish := b.operation(ctx)
					// RabbitMQ 3.x returns NO_ROUTE for a mandatory Direct Reply-To
					// publication even while delivering it. Publisher confirmation
					// still applies; delivery to the requester is not acknowledged.
					mandatory := !strings.HasPrefix(delivery.ReplyTo, "amq.rabbitmq.reply-to.")
					err = publisher.publish(op, "", delivery.ReplyTo, mandatory, amqp.Publishing{ContentType: "application/json", Body: response, CorrelationId: delivery.CorrelationId})
					finish()
					if err != nil {
						result <- err
						return
					}
				}
				if err = delivery.Ack(false); err != nil {
					result <- err
					return
				}
			}
		}
	}()
	return result, nil
}
