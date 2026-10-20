package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

const (
	// Scheme preserves existing profiles and callbacks. The aliases select the
	// client implementation while using the same Beaconcrypt server protocol.
	Scheme       = "beaconcrypt"
	SchemeNative = "Native"
	SchemeWASM   = "WASM"
	// Completed messages are base64 encoded inside the durable JSON result.
	// Keep ample room below the 16 MiB result limit for framing and metadata.
	MaxProviderMessageBytes = 8 << 20
)

type profile struct {
	OperationID int `json:"operation_id"`
}

type session struct {
	OperationID int    `json:"operation_id"`
	ProfileRef  string `json:"profile_ref"`
	KeyID       uint64 `json:"key_id"`
	Revoked     bool   `json:"revoked,omitempty"`
	// A native failure with an unsafe continuation outcome is provider policy.
	// Persist its receipt with the checkpoint instead of fencing Mythic routing.
	UnresolvedRequestID string `json:"unresolved_request_id,omitempty"`
}

type requestIndex struct {
	Digest      string `json:"digest"`
	OperationID int    `json:"operation_id"`
	Method      string `json:"method"`
	SessionRef  string `json:"session_ref,omitempty"`
}

type ownerData struct {
	Version     int                     `json:"version"`
	OperationID int                     `json:"operation_id,omitempty"`
	ServerKID   uint64                  `json:"server_kid"`
	IdentityPK  []byte                  `json:"identity_pk"`
	Profiles    map[string]profile      `json:"profiles"`
	Sessions    map[string]session      `json:"sessions"`
	Requests    map[string]requestIndex `json:"requests"`
}

type Engine struct {
	campaignID  int
	mu          sync.Mutex
	config      Config
	factory     Factory
	store       Store
	key         wire.StateKey
	head        wire.StoredState
	data        ownerData
	native      Native
	ownerKnown  bool
	initialized bool
	fenced      bool
	closed      bool
}

func New(config Config, factory Factory, store Store) (*Engine, error) {
	if factory == nil || store == nil {
		return nil, errors.New("native factory and storage are required")
	}
	if config.Namespace == "" {
		config.Namespace = "beaconcrypt"
	}
	if config.StateID == "" {
		config.StateID = "server"
	}
	if !validStatePart(config.Namespace, wire.MaxNamespaceBytes) || !validStatePart(config.StateID, wire.MaxStateIDBytes) {
		return nil, errors.New("invalid state namespace or identifier")
	}
	if config.MaxProfiles == 0 {
		config.MaxProfiles = 1000
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 1000
	}
	if config.MaxRequests == 0 {
		config.MaxRequests = 5000
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = 1 << 20
	}
	if config.ResultRetentionSeconds == 0 {
		config.ResultRetentionSeconds = 86400
	}
	if config.MaxProfiles < 1 || config.MaxSessions < 1 || config.MaxRequests < 1 || config.MaxMessageBytes < 1 || config.MaxMessageBytes > MaxProviderMessageBytes || config.ResultRetentionSeconds < 1 {
		return nil, errors.New("invalid provider admission limits")
	}
	return &Engine{config: config, factory: factory, store: store, key: wire.StateKey{Namespace: config.Namespace, StateID: config.StateID}}, nil
}

func validStatePart(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, c := range value {
		allowed := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:/-", c)
		if !allowed {
			return false
		}
	}
	return true
}

// SupportedSchemes returns independently owned capability names.
func SupportedSchemes() []string { return []string{Scheme, SchemeNative, SchemeWASM} }

func isBeaconcryptScheme(scheme string) bool {
	switch scheme {
	case Scheme, SchemeNative, SchemeWASM:
		return true
	default:
		return false
	}
}

func (e *Engine) Capabilities() wire.Capabilities {
	return wire.Capabilities{APIVersion: wire.APIVersion, Schemes: SupportedSchemes(), Establishment: "single_round", SessionPersistence: "durable", MaxMessageBytes: e.config.MaxMessageBytes, ResultRetentionSeconds: e.config.ResultRetentionSeconds}
}

func (e *Engine) Activate(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activate(ctx, false)
}

func (e *Engine) activate(ctx context.Context, provision bool) error {
	if e.closed {
		return errors.New("provider engine is closed")
	}
	if e.fenced {
		return wire.ErrStaleWriter
	}
	if e.native != nil {
		return nil
	}
	state, err := e.store.Load(ctx, e.key)
	if errors.Is(err, wire.ErrNotFound) {
		if !e.config.Initialize && !provision || e.initialized || e.ownerKnown {
			return fmt.Errorf("established owner state is unavailable: %w", err)
		}
		state, err = e.initialize(ctx)
	} else if err == nil && e.config.Initialize && !e.initialized && !e.ownerKnown {
		return wire.ErrAlreadyExists
	}
	if err != nil {
		return err
	}
	if e.ownerKnown && state.OwnerEpoch != e.head.OwnerEpoch {
		e.fenced = true
		return wire.ErrStaleWriter
	}
	if _, err := e.decodeData(state.ProviderJSON); err != nil {
		return err
	}
	if len(state.StateBlob) == 0 || len(state.StateBlob) > wire.MaxStateBlobBytes {
		return errors.New("invalid owner checkpoint")
	}
	acquired, err := e.store.Acquire(ctx, wire.AcquireStateRequest{StateKey: e.key, ExpectedOwnerEpoch: state.OwnerEpoch})
	if err != nil {
		// A lost acknowledgement cannot establish which worker holds the new
		// epoch. This instance never assumes ownership from an observed counter.
		e.fenced = true
		return fmt.Errorf("acquire owner requires a fresh worker after failure: %w", err)
	}
	e.head, e.ownerKnown = acquired, true
	// The prior owner can commit between Load and Acquire. Metadata and native
	// bytes must come from the same acquired row.
	data, err := e.decodeData(acquired.ProviderJSON)
	if err != nil {
		return err
	}
	if len(acquired.StateBlob) == 0 || len(acquired.StateBlob) > wire.MaxStateBlobBytes {
		return errors.New("invalid acquired owner checkpoint")
	}
	native, err := e.factory.Restore(acquired.StateBlob)
	if err != nil {
		return fmt.Errorf("restore owner checkpoint: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			native.Close()
		}
	}()
	publicKey, err := native.IdentityPK()
	if err != nil || !bytes.Equal(publicKey, data.IdentityPK) {
		return errors.New("restored server identity does not match owner metadata")
	}
	checkpoint, err := native.Export()
	if err != nil || len(checkpoint) == 0 || len(checkpoint) > wire.MaxStateBlobBytes {
		return errors.New("cannot export activated owner checkpoint")
	}
	metadata, err := json.Marshal(data)
	if err != nil {
		return err
	}
	activationID := "activation:" + strconv.FormatInt(acquired.OwnerEpoch, 10)
	sum := sha256.Sum256(append([]byte(activationID+":"+strconv.FormatInt(acquired.Revision, 10)+":"), checkpoint...))
	digest := hex.EncodeToString(sum[:])
	result, err := e.store.Commit(ctx, wire.CommitStateRequest{StateKey: e.key, OwnerEpoch: acquired.OwnerEpoch, ExpectedRevision: acquired.Revision,
		RequestID: activationID, InputDigest: digest, StateBlob: checkpoint, ProviderJSON: metadata, Result: json.RawMessage(`{"activated":true}`)})
	if err != nil {
		if errors.Is(err, wire.ErrStaleWriter) {
			e.fenced = true
			return err
		}
		saved, lookupErr := e.store.LookupResult(ctx, wire.LookupResultRequest{StateKey: e.key, RequestID: activationID, InputDigest: digest})
		if lookupErr != nil {
			return fmt.Errorf("activated checkpoint commit remains unresolved: %w", err)
		}
		result.Revision = saved.Revision
	}
	e.head = acquired
	e.head.StateBlob, e.head.ProviderJSON, e.head.Revision = checkpoint, metadata, result.Revision
	e.data, e.native, keep = data, native, true
	return nil
}

func (e *Engine) initialize(ctx context.Context) (wire.StoredState, error) {
	native, err := e.factory.New(e.config.ServerKID)
	if err != nil {
		return wire.StoredState{}, err
	}
	defer native.Close()
	publicKey, err := native.IdentityPK()
	if err != nil || len(publicKey) == 0 {
		return wire.StoredState{}, errors.New("cannot obtain server identity")
	}
	checkpoint, err := native.Export()
	if err != nil || len(checkpoint) == 0 || len(checkpoint) > wire.MaxStateBlobBytes {
		return wire.StoredState{}, errors.New("cannot export new server identity")
	}
	data := ownerData{Version: 1, OperationID: e.campaignID, ServerKID: e.config.ServerKID, IdentityPK: publicKey, Profiles: map[string]profile{}, Sessions: map[string]session{}, Requests: map[string]requestIndex{}}
	metadata, err := json.Marshal(data)
	if err != nil {
		return wire.StoredState{}, err
	}
	// Creation is explicit, never an automatic fallback for missing live state.
	e.initialized = true
	created, err := e.store.Create(ctx, wire.CreateStateRequest{StateKey: e.key, StateBlob: checkpoint, ProviderJSON: metadata})
	if err != nil {
		return wire.StoredState{}, fmt.Errorf("initialize durable owner: %w", err)
	}
	return created, nil
}

func (e *Engine) decodeData(raw json.RawMessage) (ownerData, error) {
	var data ownerData
	if len(raw) == 0 || len(raw) > wire.MaxProviderJSONBytes || json.Unmarshal(raw, &data) != nil || data.Version != 1 || data.ServerKID != e.config.ServerKID || len(data.IdentityPK) == 0 || data.Profiles == nil || data.Sessions == nil || data.Requests == nil {
		return data, errors.New("invalid provider owner metadata")
	}
	if data.OperationID != e.campaignID {
		return data, errors.New("owner metadata belongs to a different campaign")
	}
	if len(data.Profiles) > e.config.MaxProfiles || len(data.Sessions) > e.config.MaxSessions || ordinaryRequestCount(data) > e.config.MaxRequests {
		return data, errors.New("owner metadata exceeds configured admission limits")
	}
	for ref, p := range data.Profiles {
		if ref == "" || p.OperationID < 1 || e.campaignID != 0 && p.OperationID != e.campaignID {
			return data, errors.New("invalid persisted profile ownership")
		}
	}
	revocations := make(map[string]bool)
	for _, r := range data.Requests {
		if len(r.Digest) != 64 || r.OperationID < 1 || r.Method == "" || e.campaignID != 0 && r.OperationID != e.campaignID {
			return data, errors.New("invalid persisted request index")
		}
		if r.Method == wire.RevokeSession {
			s, ok := data.Sessions[r.SessionRef]
			if !ok || !s.Revoked || s.OperationID != r.OperationID || revocations[r.SessionRef] {
				return data, errors.New("invalid persisted revocation receipt")
			}
			revocations[r.SessionRef] = true
		}
	}
	for ref, s := range data.Sessions {
		p, ok := data.Profiles[s.ProfileRef]
		if !ok || p.OperationID != s.OperationID || s.OperationID < 1 {
			return data, errors.New("invalid persisted session ownership")
		}
		if s.UnresolvedRequestID != "" {
			id, err := uuid.Parse(s.UnresolvedRequestID)
			request, ok := data.Requests[s.UnresolvedRequestID]
			if err != nil || id.String() != s.UnresolvedRequestID || !ok || request.SessionRef != ref || request.Method != wire.Open && request.Method != wire.Seal {
				return data, errors.New("invalid persisted session failure receipt")
			}
		}
	}
	if !metadataFitsData(data) {
		return data, errors.New("owner metadata lacks its reserved revocation capacity")
	}
	return data, nil
}

func (e *Engine) discard() {
	if e.native != nil {
		e.native.Close()
		e.native = nil
	}
	e.data = ownerData{}
}

func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.discard()
	e.closed = true
}
