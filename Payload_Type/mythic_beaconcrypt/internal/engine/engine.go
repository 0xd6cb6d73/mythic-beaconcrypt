package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/0xd6cb6d73/mythic-beaconcrypt/internal/wire"
	"github.com/google/uuid"
)

func reply(request wire.Request) wire.Response {
	return wire.Response{APIVersion: wire.APIVersion, RequestID: request.RequestID, OperationScopeID: request.OperationScopeID, AuthContext: request.AuthContext, Success: true}
}

func failure(request wire.Request, code, message, outcome string) wire.Response {
	response := reply(request)
	response.Success = false
	response.Error = &wire.Failure{Code: code, Message: message, Outcome: outcome}
	return response
}

func nativeFailure(request wire.Request, message string, err error) wire.Response {
	code := "native_failure"
	if errors.Is(err, ErrNativePersistence) {
		code = "native_persistence_failure"
	}
	return failure(request, code, message, "unresolved")
}

// Handle keeps native work, metadata changes, and the immutable result under
// one owner mutex. The request's transient auth context never enters storage.
func (e *Engine) Handle(ctx context.Context, request wire.Request) wire.Response {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := request.Validate(); err != nil {
		return failure(request, "invalid_input", err.Error(), "rejected")
	}
	if len(request.Message) > e.config.MaxMessageBytes {
		return failure(request, "invalid_input", "provider message exceeds configured limit", "rejected")
	}
	if request.Scheme != "" && request.Scheme != Scheme {
		return failure(request, "invalid_input", "unsupported cryptographic scheme", "rejected")
	}
	if e.campaignID != 0 && request.OperationScopeID != e.campaignID {
		return failure(request, "invalid_input", "operation scope does not match this campaign", "rejected")
	}
	provision := e.campaignID != 0 && request.Method == wire.PrepareProfile && request.Namespace == "" && request.StateID == ""
	if err := e.activate(ctx, provision); err != nil {
		return failure(request, "owner_unavailable", "durable owner is unavailable; recovery is required", "unresolved")
	}
	// Authorize cached outcomes against the current owner as well. A replaced
	// worker must not keep serving results using stale revocation metadata.
	current, err := e.store.Load(ctx, e.key)
	if err != nil {
		e.discard()
		return failure(request, "storage_unavailable", "cannot verify current owner", "unresolved")
	}
	if current.OwnerEpoch != e.head.OwnerEpoch || current.Revision != e.head.Revision {
		if current.OwnerEpoch != e.head.OwnerEpoch {
			e.fenced = true
		}
		e.discard()
		return failure(request, "stale_owner", "provider owner was replaced or changed", "unresolved")
	}
	digest, err := request.Digest()
	if err != nil {
		return failure(request, "invalid_input", "cannot digest request", "rejected")
	}
	if index, ok := e.data.Requests[request.RequestID]; ok {
		if index.Digest != digest {
			return failure(request, "request_conflict", "request ID has different immutable input", "rejected")
		}
		if err := e.authorizeIndex(index, request.OperationScopeID); err != nil {
			return failure(request, "unavailable_session", err.Error(), "rejected")
		}
	}
	if err := e.authorize(request); err != nil {
		return failure(request, "unavailable_session", err.Error(), "rejected")
	}
	if request.Method == wire.Open || request.Method == wire.Seal {
		s := e.data.Sessions[request.SessionRef]
		if s.UnresolvedRequestID != "" && s.UnresolvedRequestID != request.RequestID {
			return failure(request, "session_unresolved", "native session requires reestablishment after an unresolved failure", "unresolved")
		}
	}
	// Queries observe the latest committed outcome and do not grow the durable
	// request journal. In particular an unresolved lookup must remain pollable.
	if request.Method == wire.Describe || request.Method == wire.GetOperation {
		response, _, _ := e.perform(ctx, request)
		return response
	}
	saved, err := e.store.LookupResult(ctx, wire.LookupResultRequest{StateKey: e.key, RequestID: request.RequestID, InputDigest: digest})
	if err == nil {
		return e.restoreResponse(request, saved.Result)
	}
	if errors.Is(err, wire.ErrRequestConflict) {
		return failure(request, "request_conflict", "request ID has different immutable input", "rejected")
	}
	if !errors.Is(err, wire.ErrNotFound) {
		e.discard()
		return failure(request, "storage_unavailable", "cannot determine the prior request outcome", "unresolved")
	}
	if _, indexed := e.data.Requests[request.RequestID]; indexed {
		return failure(request, "result_unavailable", "a committed result is missing or expired", "unresolved")
	}
	if request.Method == wire.RevokeSession && e.data.Sessions[request.SessionRef].Revoked {
		return failure(request, "already_revoked", "session is already revoked", "rejected")
	}
	if request.Method != wire.RevokeSession && ordinaryRequestCount(e.data) >= e.config.MaxRequests {
		return failure(request, "capacity", "durable request admission limit reached", "rejected")
	}
	e.data.Requests[request.RequestID] = requestIndex{Digest: digest, OperationID: request.OperationScopeID, Method: request.Method, SessionRef: request.SessionRef}
	// A first revoke consumes its pre-reserved index and tombstone space after
	// perform marks the session revoked. It never needs native work.
	if request.Method != wire.RevokeSession && !e.metadataFits() {
		delete(e.data.Requests, request.RequestID)
		return failure(request, "capacity", "provider metadata admission limit reached", "rejected")
	}
	response, usedNative, nativeFailed := e.perform(ctx, request)
	if response.SessionRef != "" {
		index := e.data.Requests[request.RequestID]
		index.SessionRef = response.SessionRef
		e.data.Requests[request.RequestID] = index
	}
	checkpoint := e.head.StateBlob
	if usedNative {
		checkpoint, err = e.native.Export()
		if err != nil || len(checkpoint) == 0 || len(checkpoint) > wire.MaxStateBlobBytes {
			e.discard()
			return failure(request, "checkpoint_unavailable", "native checkpoint could not be committed", "unresolved")
		}
		if nativeFailed && response.Error != nil && response.Error.Code == "native_failure" {
			if bytes.Equal(checkpoint, e.head.StateBlob) {
				response.Error.Outcome = "rejected"
			}
		}
	}
	if !response.Success && response.Error != nil && response.Error.Outcome == wire.OutcomeRejected {
		// Invalid unauthenticated packets must not consume durable request slots.
		// This path is valid only before native work or after byte-identical export.
		delete(e.data.Requests, request.RequestID)
		if nativeFailed {
			e.discard()
		}
		return response
	}
	// A lost AMQP acknowledgement does not enter this path: native output and
	// its receipt are committed together and can be replayed by request ID.
	// Only a native failure whose effects prevent safe continuation fences the
	// affected session; other sessions sharing the campaign remain available.
	if usedNative && !response.Success && response.Error != nil && response.Error.Outcome != wire.OutcomeRejected && (request.Method == wire.Open || request.Method == wire.Seal) {
		s := e.data.Sessions[request.SessionRef]
		s.UnresolvedRequestID = request.RequestID
		e.data.Sessions[request.SessionRef] = s
	}
	if !e.metadataFits() {
		e.discard()
		return failure(request, "capacity", "native operation exceeded provider metadata capacity", "unresolved")
	}
	return e.commit(ctx, request, digest, response, checkpoint, nativeFailed)
}

func (e *Engine) authorizeIndex(index requestIndex, scope int) error {
	if index.OperationID != scope {
		return errors.New("request belongs to a different operation")
	}
	if index.SessionRef != "" && index.Method != wire.RevokeSession {
		s, ok := e.data.Sessions[index.SessionRef]
		if !ok || s.OperationID != scope || s.Revoked {
			return errors.New("request session is unavailable or revoked")
		}
	}
	return nil
}

func (e *Engine) authorize(request wire.Request) error {
	if request.Namespace != "" && request.Namespace != e.key.Namespace || request.StateID != "" && request.StateID != e.key.StateID {
		return errors.New("state scope does not match this owner")
	}
	switch request.Method {
	case wire.BeginSession:
		p, ok := e.data.Profiles[request.ProfileRef]
		if !ok || p.OperationID != request.OperationScopeID {
			return errors.New("profile does not belong to this operation")
		}
	case wire.Open, wire.Seal, wire.RevokeSession:
		s, ok := e.data.Sessions[request.SessionRef]
		if !ok || s.OperationID != request.OperationScopeID || request.ProfileRef != "" && request.ProfileRef != s.ProfileRef || s.Revoked && request.Method != wire.RevokeSession {
			return errors.New("session is unavailable or does not belong to this operation")
		}
	}
	return nil
}

func ordinaryRequestCount(data ownerData) int {
	count := 0
	for _, index := range data.Requests {
		if index.Method != wire.RevokeSession {
			count++
		}
	}
	return count
}

func (e *Engine) metadataFits() bool { return metadataFitsData(e.data) }

// Every live session reserves enough JSON space for its first immutable revoke
// receipt, tombstone, and native-failure fence. Ordinary admission cannot spend
// that capacity. Receipts use canonical UUIDs and fixed-length SHA-256 digests.
func metadataFitsData(data ownerData) bool {
	encoded, err := json.Marshal(data)
	if err != nil {
		return false
	}
	size := len(encoded)
	for ref, s := range data.Sessions {
		if s.Revoked {
			continue
		}
		reserved := requestIndex{Digest: strings.Repeat("0", 64), OperationID: s.OperationID, Method: wire.RevokeSession, SessionRef: ref}
		entry, err := json.Marshal(map[string]requestIndex{uuid.Nil.String(): reserved})
		if err != nil {
			return false
		}
		// Removing the two map braces and adding a comma costs len(entry)-1.
		// This is conservative even when the current request map is empty.
		size += len(entry) - 1 + len(`,"revoked":true`)
		if s.UnresolvedRequestID == "" {
			size += len(`,"unresolved_request_id":"00000000-0000-0000-0000-000000000000"`)
		}
		if size > wire.MaxProviderJSONBytes {
			return false
		}
	}
	return size <= wire.MaxProviderJSONBytes
}

// The bools report whether native state may have changed and whether the handle
// must be recycled after the authoritative export has been recorded.
func (e *Engine) perform(ctx context.Context, request wire.Request) (wire.Response, bool, bool) {
	response := reply(request)
	switch request.Method {
	case wire.Describe:
		response.ProviderJSON, _ = json.Marshal(e.Capabilities())
	case wire.PrepareProfile:
		if request.Scheme != Scheme {
			return failure(request, "invalid_input", "scheme must be beaconcrypt", "rejected"), false, false
		}
		if len(e.data.Profiles) >= e.config.MaxProfiles {
			return failure(request, "capacity", "profile admission limit reached", "rejected"), false, false
		}
		// This provider has no request-selected identity or algorithm knobs.
		var config map[string]json.RawMessage
		if len(request.ProviderJSON) > 0 && (json.Unmarshal(request.ProviderJSON, &config) != nil || len(config) != 0) {
			return failure(request, "invalid_input", "unsupported profile configuration", "rejected"), false, false
		}
		profileRef := uuid.NewString()
		e.data.Profiles[profileRef] = profile{OperationID: request.OperationScopeID}
		material, _ := json.Marshal(struct {
			Version         int    `json:"version"`
			ServerKID       string `json:"server_kid"`
			ServerPublicKey []byte `json:"server_public_key"`
		}{1, strconv.FormatUint(e.config.ServerKID, 10), e.data.IdentityPK})
		enc, dec := bytes.Clone(material), bytes.Clone(material)
		response.ProfileRef, response.Namespace, response.StateID = profileRef, e.key.Namespace, e.key.StateID
		response.AgentConfig, response.EncKey, response.DecKey = material, &enc, &dec
	case wire.BeginSession:
		return e.begin(request)
	case wire.Open:
		s := e.data.Sessions[request.SessionRef]
		advertised, err := e.factory.SenderKeyID(request.Message)
		if err != nil || advertised != s.KeyID {
			return failure(request, "route_mismatch", "packet does not belong to the routed session", "rejected"), false, false
		}
		update, err := e.native.Decrypt(request.Message)
		if err != nil {
			return nativeFailure(request, "native receive failed", err), true, true
		}
		if update.KeyID != s.KeyID {
			return failure(request, "identity_mismatch", "authenticated sender differs from the routed session", "unresolved"), true, true
		}
		response.Message = update.Data
	case wire.Seal:
		s := e.data.Sessions[request.SessionRef]
		update, err := e.native.Encrypt(s.KeyID, request.Message)
		if err != nil {
			return nativeFailure(request, "native send failed", err), true, true
		}
		if update.KeyID != s.KeyID {
			return failure(request, "identity_mismatch", "native recipient differs from the routed session", "unresolved"), true, true
		}
		response.Message = update.Data
	case wire.RevokeSession:
		s := e.data.Sessions[request.SessionRef]
		s.Revoked = true
		e.data.Sessions[request.SessionRef] = s
		response.ProviderJSON = json.RawMessage(`{"revoked":true}`)
	case wire.GetOperation:
		index, ok := e.data.Requests[request.LookupRequestID]
		if !ok {
			return failure(request, "result_unavailable", "the original request outcome is unknown", "unresolved"), false, false
		}
		if err := e.authorizeIndex(index, request.OperationScopeID); err != nil {
			return failure(request, "unavailable_session", err.Error(), "rejected"), false, false
		}
		saved, err := e.store.LookupResult(ctx, wire.LookupResultRequest{StateKey: e.key, RequestID: request.LookupRequestID, InputDigest: index.Digest})
		if err != nil {
			return failure(request, "result_unavailable", "the original result cannot be recovered", "unresolved"), false, false
		}
		response = e.restoreResponse(request, saved.Result)
	default:
		return failure(request, "invalid_input", "unsupported operation", "rejected"), false, false
	}
	return response, request.Method == wire.Open || request.Method == wire.Seal, false
}

func (e *Engine) begin(request wire.Request) (wire.Response, bool, bool) {
	if len(e.data.Sessions) >= e.config.MaxSessions {
		return failure(request, "capacity", "session admission limit reached", "rejected"), false, false
	}
	var initial struct {
		Action    string `json:"action"`
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}
	if json.Unmarshal(request.Message, &initial) != nil || initial.Action != "staging" || strings.TrimSpace(initial.SessionID) == "" || len(initial.SessionID) > 1024 {
		return failure(request, "invalid_input", "invalid staging request", "rejected"), false, false
	}
	registration, err := base64.StdEncoding.Strict().DecodeString(initial.Data)
	if err != nil || len(registration) == 0 {
		return failure(request, "invalid_input", "invalid registration encoding", "rejected"), false, false
	}
	ref := uuid.NewString()
	// Preflight the complete successful mapping, including the largest possible
	// key ID and the request's eventual session reference, before registration.
	e.data.Sessions[ref] = session{OperationID: request.OperationScopeID, ProfileRef: request.ProfileRef, KeyID: ^uint64(0)}
	index := e.data.Requests[request.RequestID]
	index.SessionRef = ref
	e.data.Requests[request.RequestID] = index
	removeProvisional := func() {
		delete(e.data.Sessions, ref)
		index.SessionRef = ""
		e.data.Requests[request.RequestID] = index
	}
	if !e.metadataFits() {
		removeProvisional()
		return failure(request, "capacity", "session metadata admission limit reached", "rejected"), false, false
	}
	message, _ := json.Marshal(struct {
		Action    string `json:"action"`
		Status    string `json:"status"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
	}{"staging", "success", request.NextUUID, initial.SessionID})
	registered, err := e.native.Register(registration, message)
	if err != nil {
		removeProvisional()
		return nativeFailure(request, "native registration failed", err), true, true
	}
	if len(registered.Data) == 0 {
		removeProvisional()
		return failure(request, "native_failure", "native registration omitted its response", "unresolved"), true, true
	}
	// Never let a reused native key ID make an old opaque reference alias a
	// replacement ratchet. The previous incarnation becomes unavailable.
	for oldRef, old := range e.data.Sessions {
		if oldRef != ref && old.KeyID == registered.KeyID {
			old.Revoked = true
			e.data.Sessions[oldRef] = old
		}
	}
	e.data.Sessions[ref] = session{OperationID: request.OperationScopeID, ProfileRef: request.ProfileRef, KeyID: registered.KeyID}
	outer, _ := json.Marshal(struct {
		Action    string `json:"action"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
		Data      string `json:"data"`
	}{"staging", request.NextUUID, initial.SessionID, base64.StdEncoding.EncodeToString(registered.Data)})
	response := reply(request)
	response.SessionRef, response.Namespace, response.StateID, response.Message = ref, e.key.Namespace, e.key.StateID, outer
	return response, true, false
}

func (e *Engine) restoreResponse(request wire.Request, raw json.RawMessage) wire.Response {
	var response wire.Response
	if json.Unmarshal(raw, &response) != nil || response.APIVersion != wire.APIVersion || response.OperationScopeID != request.OperationScopeID {
		return failure(request, "invalid_result", "saved request result is invalid", "unresolved")
	}
	if id, err := uuid.Parse(response.RequestID); err != nil || id.String() != response.RequestID {
		return failure(request, "invalid_result", "saved request identifier is invalid", "unresolved")
	}
	response.RequestID, response.AuthContext = request.RequestID, request.AuthContext
	if !response.Success {
		if response.Error == nil || response.Error.Code == "" || response.Error.Outcome != "" && response.Error.Outcome != wire.OutcomeRejected && response.Error.Outcome != wire.OutcomeUnresolved {
			return failure(request, "invalid_result", "saved failure is invalid", "unresolved")
		}
		// Validate checks payload bounds and routing only on successful replies.
		// Check those fields independently before preserving a business failure.
		check := response
		check.Success, check.Error = true, nil
		checkRequest := request
		checkRequest.Method = wire.GetOperation
		if err := check.Validate(checkRequest); err != nil {
			return failure(request, "invalid_result", "saved failure does not match", "unresolved")
		}
	} else if err := response.Validate(request); err != nil {
		return failure(request, "invalid_result", "saved request result does not match", "unresolved")
	}
	return response
}

func (e *Engine) commit(ctx context.Context, request wire.Request, digest string, response wire.Response, checkpoint []byte, retire bool) wire.Response {
	response.AuthContext = ""
	encoded, err := json.Marshal(response)
	if err != nil || len(encoded) > wire.MaxResultBytes {
		e.discard()
		return failure(request, "result_unavailable", "operation result cannot be committed", "unresolved")
	}
	metadata, err := json.Marshal(e.data)
	if err != nil {
		e.discard()
		return failure(request, "result_unavailable", "owner metadata cannot be committed", "unresolved")
	}
	committed, err := e.store.Commit(ctx, wire.CommitStateRequest{StateKey: e.key, ExpectedRevision: e.head.Revision, OwnerEpoch: e.head.OwnerEpoch,
		RequestID: request.RequestID, InputDigest: digest, StateBlob: checkpoint, ProviderJSON: metadata, Result: encoded})
	if err != nil {
		e.discard()
		if errors.Is(err, wire.ErrStaleWriter) {
			e.fenced = true
		}
		saved, lookupErr := e.store.LookupResult(ctx, wire.LookupResultRequest{StateKey: e.key, RequestID: request.RequestID, InputDigest: digest})
		if lookupErr == nil {
			return e.restoreResponse(request, saved.Result)
		}
		if errors.Is(err, wire.ErrRequestConflict) || errors.Is(lookupErr, wire.ErrRequestConflict) {
			return failure(request, "request_conflict", "request ID has different immutable input", "rejected")
		}
		return failure(request, "storage_unavailable", "operation commit remains unresolved", "unresolved")
	}
	if committed.Cached {
		e.discard()
		return e.restoreResponse(request, committed.Result)
	}
	e.head.StateBlob, e.head.ProviderJSON, e.head.Revision = bytes.Clone(checkpoint), bytes.Clone(metadata), committed.Revision
	if retire {
		e.discard()
	}
	return e.restoreResponse(request, committed.Result)
}
