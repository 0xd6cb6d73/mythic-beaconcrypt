package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/engine"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/storage"
	testbroker "github.com/0xd6cb6d73/mythic-beaconcrypt/internal/testsupport/broker"
	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/MythicMeta/MythicContainer/rabbitmq"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type lifecycleConfig struct {
	Config
	Engine engine.Config
}

// This exercises process composition and queue lifecycle, with no native
// cryptography or duplicated session/ratchet tests. The fake Mythic peer speaks
// the JSON storage wire protocol and SDK authorization headers through real RabbitMQ.
func TestRunLifecycleOverAMQP(t *testing.T) {
	address := os.Getenv("BEACONCRYPT_AMQP_TEST_URL")
	if address == "" {
		t.Skip("set BEACONCRYPT_AMQP_TEST_URL to an isolated RabbitMQ broker")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	peer, err := testbroker.Connect(ctx, address)
	if err != nil {
		t.Fatal(err)
	}
	defer closeLifecycleBroker(t, peer)
	config := lifecycleConfig{Config: Config{Name: "beaconcrypt-test-" + uuid.NewString(), AMQPURL: address, RPCTimeout: 2 * time.Second, Description: "Lifecycle test provider", Version: "1.0.0"}, Engine: engine.Config{Namespace: "test", StateID: "owner", MaxMessageBytes: 4096, ResultRetentionSeconds: 3600}}
	config.Capabilities = wire.Capabilities{APIVersion: wire.APIVersion, Schemes: []string{engine.Scheme}, Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: config.Engine.MaxMessageBytes, ResultRetentionSeconds: config.Engine.ResultRetentionSeconds}
	route, err := wire.RoutingKey(config.Name)
	if err != nil {
		t.Fatal(err)
	}
	var syncs atomic.Int32
	_, err = peer.ConsumeRPC(ctx, SyncRoute, func(ctx context.Context, body []byte) ([]byte, error) {
		var message struct {
			ContainerVersion string `json:"container_version"`
			Container        struct {
				Name         string            `json:"name"`
				Type         string            `json:"type"`
				Capabilities wire.Capabilities `json:"crypto_capabilities"`
			} `json:"consuming_container"`
		}
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, err
		}
		if message.ContainerVersion != ContainerVersion || message.Container.Name != config.Name || message.Container.Type != "crypto" || message.Container.Capabilities.MaxMessageBytes != config.Engine.MaxMessageBytes {
			return nil, errors.New("invalid crypto worker sync")
		}
		probe, err := testbroker.Connect(ctx, address)
		if err != nil {
			return nil, err
		}
		defer closeLifecycleBroker(t, probe)
		for _, queue := range []string{route, config.Name + "_consuming_container_rpc_resync", config.Name + "_container_on_start"} {
			noop := func(context.Context, []byte) ([]byte, error) { return []byte(`{}`), nil }
			var probeErr error
			if strings.HasSuffix(queue, "_container_on_start") {
				_, probeErr = probe.ConsumeDirect(ctx, queue, noop)
			} else {
				_, probeErr = probe.ConsumeRPC(ctx, queue, noop)
			}
			var amqpError *amqp.Error
			if !errors.As(probeErr, &amqpError) || amqpError.Code != amqp.ResourceLocked {
				return nil, fmt.Errorf("worker did not exclusively bind lifecycle queue %s: %w", queue, probeErr)
			}
		}
		syncs.Add(1)
		return []byte(`{"success":true}`), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	durable := &lifecycleStorage{name: config.Name, syncs: &syncs, results: map[string]wire.OperationResult{}, secondActivation: make(chan struct{})}
	_, err = peer.ConsumeRPC(ctx, storage.Route, durable.handle)
	if err != nil {
		t.Fatal(err)
	}
	worker := startLifecycleWorker(t, ctx, config, "create")
	waitForLifecycleSync(t, ctx, worker, &syncs, 1)
	if durable.acquires.Load() != 0 {
		t.Fatal("startup created a campaign before profile preparation")
	}
	before := durable.acquires.Load()
	duplicate := startLifecycleWorker(t, ctx, config, "duplicate")
	duplicate.wait(t)
	if durable.acquires.Load() != before {
		t.Fatal("duplicate SDK worker stole owner fence before acquiring exclusive queues")
	}
	invalidReply, err := peer.Call(ctx, route, []byte(`{"success":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var rejected struct {
		Success bool `json:"success"`
	}
	if json.Unmarshal(invalidReply, &rejected) != nil || rejected.Success {
		t.Fatal("input without Mythic authorization was accepted")
	}
	request := wire.Request{APIVersion: wire.APIVersion, RequestID: uuid.NewString(), OperationScopeID: 17, Method: wire.Describe, AuthContext: "mctx_lifecycle-campaign-17"}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx := rabbitmq.NewContextWithAuthToken(ctx, request.AuthContext)
	reply, err := peer.Call(requestCtx, route, requestJSON)
	if err != nil {
		t.Fatal(err)
	}
	var response wire.Response
	if err = json.Unmarshal(reply, &response); err != nil {
		t.Fatal(err)
	}
	if err = response.Validate(request); err != nil {
		t.Fatal(err)
	}
	var capabilities wire.Capabilities
	if err = json.Unmarshal(response.ProviderJSON, &capabilities); err != nil {
		t.Fatal(err)
	}
	if capabilities.MaxMessageBytes != config.Engine.MaxMessageBytes || capabilities.ResultRetentionSeconds != config.Engine.ResultRetentionSeconds {
		t.Fatal("business response differs from synced capabilities")
	}
	// An accepted state-changing operation crosses SDK RPC, the JSON storage
	// API, and the atomic provider journal while retaining only business data.
	accepted := request
	accepted.RequestID, accepted.Method, accepted.Scheme = uuid.NewString(), wire.PrepareProfile, engine.Scheme
	acceptedJSON, err := json.Marshal(accepted)
	if err != nil {
		t.Fatal(err)
	}
	acceptedReply, err := peer.Call(requestCtx, route, acceptedJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(acceptedReply, &response); err != nil {
		t.Fatal(err)
	}
	if err = response.Validate(accepted); err != nil {
		t.Fatal(err)
	}
	if response.StateID != "owner/campaign/17" || durable.acquires.Load() != 1 {
		t.Fatal("profile preparation did not create exactly one campaign owner")
	}
	resync, err := peer.Call(ctx, config.Name+"_consuming_container_rpc_resync", []byte(`{"name":"`+config.Name+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(resync) != `{"success":true}` || syncs.Load() != 2 {
		t.Fatalf("resync did not use registered crypto lifecycle: %s", resync)
	}
	if err = peer.Publish(ctx, config.Name+"_container_on_start", []byte(`{"container_name":"`+config.Name+`","apitoken":"startup-token-must-not-be-retained"}`)); err != nil {
		t.Fatal(err)
	}
	// Closing the captured SDK connection must stop this worker; an SDK
	// reconnect must never preserve a live native owner in the same process.
	worker.control(t, "disconnect")
	worker.wait(t)

	// Retrying the prepared profile restores only its campaign and returns the
	// committed result. Startup itself does not acquire campaign state.
	restored := startLifecycleWorker(t, ctx, config, "restore")
	waitForLifecycleSync(t, ctx, restored, &syncs, 3)
	if durable.acquires.Load() != 1 {
		t.Fatal("restart eagerly acquired campaign state")
	}
	cachedReply, err := peer.Call(requestCtx, route, acceptedJSON)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(cachedReply, &response); err != nil {
		t.Fatal(err)
	}
	if !response.Success || response.StateID != "owner/campaign/17" {
		t.Fatal("restored campaign did not return its retained profile")
	}
	select {
	case <-durable.secondActivation:
	case <-ctx.Done():
		t.Fatal("campaign was not restored after restart")
	}
	restored.control(t, "stop")
	restored.wait(t)

	durable.mu.Lock()
	defer durable.mu.Unlock()
	if _, ok := durable.results[accepted.RequestID]; !ok {
		t.Fatal("accepted profile result was not committed")
	}
	for _, result := range durable.results {
		if strings.Contains(string(result.Result), request.AuthContext) || strings.Contains(string(result.Result), "startup-token-must-not-be-retained") {
			t.Fatal("transient authorization persisted in immutable result")
		}
	}
}

// SDK connections and queue registrations are process-wide singletons. Each
// lifecycle starts in a fresh test subprocess, exactly as the deployed worker.
func TestSDKLifecycleWorker(t *testing.T) {
	mode := os.Getenv("BEACONCRYPT_INTERNAL_TEST_WORKER")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	var config lifecycleConfig
	if err := json.Unmarshal([]byte(os.Getenv("BEACONCRYPT_INTERNAL_TEST_CONFIG")), &config); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		input := bufio.NewScanner(os.Stdin)
		for input.Scan() {
			switch input.Text() {
			case "stop":
				cancel()
				return
			case "disconnect":
				conn, err := rabbitmq.RabbitMQConnection.GetConnection()
				if err == nil {
					_ = conn.CloseDeadline(time.Now().Add(time.Second))
				}
				return
			}
		}
	}()
	factory := &lifecycleFactory{}
	err := Run(ctx, config.Config, func(store storage.Store) (Backend, error) {
		return engine.NewCampaigns(config.Engine, factory, store)
	})
	switch mode {
	case "create":
		if err == nil || factory.created.Load() != 1 || factory.restored.Load() != 1 {
			t.Fatalf("lazy campaign creation failed: error=%v created=%d restored=%d", err, factory.created.Load(), factory.restored.Load())
		}
	case "restore":
		if err == nil || factory.created.Load() != 0 || factory.restored.Load() != 1 {
			t.Fatalf("restored SDK worker lifecycle failed: error=%v created=%d restored=%d", err, factory.created.Load(), factory.restored.Load())
		}
	case "duplicate":
		if err == nil || factory.created.Load() != 0 || factory.restored.Load() != 0 {
			t.Fatalf("duplicate worker reached native owner: error=%v created=%d restored=%d", err, factory.created.Load(), factory.restored.Load())
		}
	default:
		t.Fatal("unexpected subprocess mode")
	}
}

func waitForLifecycleSync(t *testing.T, ctx context.Context, worker *lifecycleWorker, syncs *atomic.Int32, count int32) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for syncs.Load() < count {
		select {
		case <-worker.done:
			t.Fatalf("SDK worker exited before sync: %s", worker.output.String())
		case <-ctx.Done():
			t.Fatal("SDK worker sync timed out")
		case <-ticker.C:
		}
	}
}

type lifecycleWorker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	output bytes.Buffer
	done   chan struct{}
	err    error
}

func startLifecycleWorker(t *testing.T, ctx context.Context, config lifecycleConfig, mode string) *lifecycleWorker {
	t.Helper()
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSDKLifecycleWorker$", "-test.timeout=25s")
	cmd.Env = append(os.Environ(), "BEACONCRYPT_INTERNAL_TEST_WORKER="+mode, "BEACONCRYPT_INTERNAL_TEST_CONFIG="+string(encoded))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	worker := &lifecycleWorker{cmd: cmd, stdin: stdin, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = &worker.output, &worker.output
	if err = cmd.Start(); err != nil {
		_ = stdin.Close()
		t.Fatal(err)
	}
	go func() { worker.err = cmd.Wait(); close(worker.done) }()
	t.Cleanup(func() { worker.cleanup(t) })
	return worker
}
func (w *lifecycleWorker) control(t *testing.T, command string) {
	t.Helper()
	if _, err := io.WriteString(w.stdin, command+"\n"); err != nil {
		t.Errorf("worker control: %v", err)
	}
}
func (w *lifecycleWorker) wait(t *testing.T) {
	t.Helper()
	select {
	case <-w.done:
		if w.err != nil {
			t.Fatalf("SDK subprocess failed: %v\n%s", w.err, w.output.String())
		}
	case <-time.After(8 * time.Second):
		if err := w.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("kill stuck worker: %v", err)
		}
		<-w.done
		t.Fatalf("SDK subprocess did not terminate\n%s", w.output.String())
	}
}
func (w *lifecycleWorker) cleanup(t *testing.T) {
	t.Helper()
	select {
	case <-w.done:
	default:
		w.control(t, "stop")
		w.wait(t)
	}
	if err := w.stdin.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Errorf("close worker input: %v", err)
	}
}
func closeLifecycleBroker(t *testing.T, broker *testbroker.Broker) {
	t.Helper()
	if err := broker.Close(); err != nil && !errors.Is(err, amqp.ErrClosed) {
		t.Errorf("close test peer: %v", err)
	}
}

type lifecycleFactory struct{ created, restored atomic.Int32 }

func (f *lifecycleFactory) New(uint64) (engine.Native, error) {
	f.created.Add(1)
	return lifecycleNative{}, nil
}
func (f *lifecycleFactory) Restore([]byte) (engine.Native, error) {
	f.restored.Add(1)
	return lifecycleNative{}, nil
}
func (*lifecycleFactory) SenderKeyID([]byte) (uint64, error) {
	return 0, errors.New("not a protocol test")
}

type lifecycleNative struct{}

func (lifecycleNative) IdentityPK() ([]byte, error) { return []byte("test-public-key"), nil }
func (lifecycleNative) Export() ([]byte, error)     { return []byte("test-native-checkpoint"), nil }
func (lifecycleNative) Register([]byte, []byte) (engine.Registration, error) {
	return engine.Registration{}, errors.New("not a protocol test")
}
func (lifecycleNative) Encrypt(uint64, []byte) (engine.Update, error) {
	return engine.Update{}, errors.New("not a protocol test")
}
func (lifecycleNative) Decrypt([]byte) (engine.Update, error) {
	return engine.Update{}, errors.New("not a protocol test")
}
func (lifecycleNative) Close() {}

type lifecycleStorage struct {
	mu               sync.Mutex
	name             string
	syncs            *atomic.Int32
	state            *wire.StoredState
	results          map[string]wire.OperationResult
	acquires         atomic.Int32
	secondActivation chan struct{}
}

func (s *lifecycleStorage) handle(ctx context.Context, body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token, ok := rabbitmq.AuthTokenFromContext(ctx); !ok || token != "mctx_lifecycle-campaign-17" {
		return nil, errors.New("storage call lost transient Mythic authorization header")
	}
	var request struct {
		APIVersion   int             `json:"api_version"`
		RequestID    string          `json:"request_id"`
		ProviderName string          `json:"provider_name"`
		Method       string          `json:"method"`
		Input        json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	if request.APIVersion != wire.APIVersion || request.ProviderName != s.name || s.syncs.Load() == 0 {
		return nil, errors.New("storage used before worker sync or with wrong provider")
	}
	var result any
	var failure *wire.Failure
	switch request.Method {
	case "load":
		if s.state == nil {
			failure = &wire.Failure{Code: "not_found"}
		} else {
			result = *s.state
		}
	case "create":
		var input wire.CreateStateRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			return nil, err
		}
		if s.state != nil {
			failure = &wire.Failure{Code: "already_exists"}
		} else {
			s.state = &wire.StoredState{StateKey: input.StateKey, StateBlob: input.StateBlob, ProviderJSON: input.ProviderJSON}
			result = *s.state
		}
	case "acquire":
		var input wire.AcquireStateRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			return nil, err
		}
		if s.state == nil || s.state.OwnerEpoch != input.ExpectedOwnerEpoch {
			failure = &wire.Failure{Code: "stale_writer"}
		} else {
			s.state.OwnerEpoch++
			s.acquires.Add(1)
			result = *s.state
		}
	case "commit":
		var input wire.CommitStateRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			return nil, err
		}
		if s.state == nil || s.state.OwnerEpoch != input.OwnerEpoch || s.state.Revision != input.ExpectedRevision {
			failure = &wire.Failure{Code: "stale_writer"}
		} else {
			s.state.Revision++
			s.state.StateBlob = input.StateBlob
			s.state.ProviderJSON = input.ProviderJSON
			s.results[input.RequestID] = wire.OperationResult{StateKey: input.StateKey, RequestID: input.RequestID, InputDigest: input.InputDigest, Revision: s.state.Revision, Result: input.Result}
			result = wire.CommitResult{Revision: s.state.Revision, Result: input.Result}
			if s.acquires.Load() == 2 && strings.HasPrefix(input.RequestID, "activation:") {
				close(s.secondActivation)
			}
		}
	case "get_result":
		var input wire.LookupResultRequest
		if err := json.Unmarshal(request.Input, &input); err != nil {
			return nil, err
		}
		if saved, ok := s.results[input.RequestID]; ok {
			if saved.InputDigest == input.InputDigest {
				result = saved
			} else {
				failure = &wire.Failure{Code: "request_conflict"}
			}
		} else {
			failure = &wire.Failure{Code: "not_found"}
		}
	default:
		return nil, errors.New("unexpected storage method")
	}
	response := map[string]any{"api_version": wire.APIVersion, "request_id": request.RequestID, "provider_name": request.ProviderName, "success": failure == nil}
	if failure != nil {
		response["error"] = failure
	} else {
		response["result"] = result
	}
	return json.Marshal(response)
}
