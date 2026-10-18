package transport

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"

	sdk "github.com/MythicMeta/MythicContainer/rabbitmq"
	amqp "github.com/rabbitmq/amqp091-go"
)

const concurrentRPCWorkers = 32

type concurrentRPC struct {
	ctx     context.Context
	route   string
	handler Handler
}

// ConsumeConcurrentRPC bounds parallel business requests on one exclusive queue.
// The SDK's ordinary RPC listener invokes handlers sequentially, so a blocked
// campaign would otherwise prevent independent campaign owners from progressing.
// Connection lifecycle and outgoing storage RPC remain owned by the SDK.
func (b *Broker) ConsumeConcurrentRPC(ctx context.Context, route string, handler Handler) (<-chan error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.registerCheck(route, handler); err != nil {
		return nil, err
	}
	b.concurrent = append(b.concurrent, concurrentRPC{ctx: ctx, route: route, handler: handler})
	return make(chan error, 1), nil
}

func (b *Broker) startConcurrentRPC(registration concurrentRPC) error {
	if b.hooks.channel == nil {
		return errors.New("SDK channel factory is unavailable")
	}
	ch, err := b.hooks.channel()
	if err != nil {
		return err
	}
	ready := false
	defer func() {
		if !ready {
			_ = ch.Close()
		}
	}()
	if err = ch.ExchangeDeclare(Exchange, "direct", true, true, false, false, nil); err != nil {
		return err
	}
	if _, err = ch.QueueDeclare(registration.route, true, true, true, false, nil); err != nil {
		return err
	}
	if err = ch.QueueBind(registration.route, registration.route, Exchange, false, nil); err != nil {
		return err
	}
	if err = ch.Qos(concurrentRPCWorkers, 0, false); err != nil {
		return err
	}
	if err = ch.Confirm(false); err != nil {
		return err
	}
	returned := ch.NotifyReturn(make(chan amqp.Return, 1))
	closed := ch.NotifyClose(make(chan *amqp.Error, 1))
	deliveries, err := ch.Consume(registration.route, "", false, true, false, false, nil)
	if err != nil {
		return err
	}
	select {
	case <-b.done:
		return errors.New("SDK worker stopped before concurrent consumer startup")
	default:
	}
	ready = true
	go func() {
		select {
		case channelErr := <-closed:
			if channelErr != nil {
				b.fail(channelErr)
			} else {
				b.fail(errors.New("SDK concurrent RPC channel closed"))
			}
		case <-b.done:
		}
	}()
	// Handler work proceeds independently; only publication confirmation is
	// serialized so mandatory returns can be associated with one exact reply.
	publisher := &sync.Mutex{}
	for range concurrentRPCWorkers {
		go func() {
			for {
				select {
				case <-b.done:
					return
				case <-registration.ctx.Done():
					return
				case delivery, ok := <-deliveries:
					if !ok {
						b.fail(errors.New("SDK concurrent RPC consumer stopped"))
						return
					}
					if err := b.handleConcurrentRPC(registration, ch, publisher, returned, delivery); err != nil {
						b.fail(err)
						return
					}
				}
			}
		}()
	}
	return nil
}

func (b *Broker) handleConcurrentRPC(registration concurrentRPC, ch *amqp.Channel, publisher *sync.Mutex, returned <-chan amqp.Return, delivery amqp.Delivery) error {
	requestCtx := registration.ctx
	if token, ok := sdk.AuthTokenFromHeaders(delivery.Headers); ok {
		requestCtx = sdk.NewContextWithAuthToken(requestCtx, token)
	}
	ctx, cancel := context.WithTimeout(requestCtx, operationTimeout)
	stop := context.AfterFunc(ctx, func() { b.fail(errors.New("SDK concurrent RPC operation timed out")) })
	defer cancel()
	defer stop()
	select {
	case <-b.done:
		return errors.New("SDK worker stopped")
	default:
	}
	body, err := registration.handler(ctx, delivery.Body)
	if err != nil || !json.Valid(body) || len(body) > MaxBodyBytes || delivery.ReplyTo == "" {
		return errors.New("invalid SDK concurrent RPC response")
	}
	publisher.Lock()
	defer publisher.Unlock()
	select {
	case <-b.done:
		return errors.New("SDK worker stopped before reply publication")
	default:
	}
	// RabbitMQ 3.x can return NO_ROUTE for mandatory Direct Reply-To replies
	// while still delivering them. Confirm broker acceptance without requiring
	// a queue route for that pseudo-address; Mythic retries lost responses.
	mandatory := !strings.HasPrefix(delivery.ReplyTo, "amq.rabbitmq.reply-to.")
	confirmation, err := ch.PublishWithDeferredConfirmWithContext(ctx, "", delivery.ReplyTo, mandatory, false, amqp.Publishing{
		ContentType: "application/json", Body: body, CorrelationId: delivery.CorrelationId,
	})
	if err != nil {
		return err
	}
	confirmed, err := confirmation.WaitContext(ctx)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("SDK concurrent RPC reply was not confirmed")
	}
	// RabbitMQ sends a mandatory return before its publication confirmation;
	// amqp091-go dispatches returns before completing deferred confirmations.
	select {
	case <-returned:
		return errors.New("SDK concurrent RPC reply was unroutable")
	default:
	}
	return delivery.Ack(false)
}
