// Contract adapted from Mythic crypto-provider API v1 at 776b0df9.
// Keep JSON fields and validation compatible with the Mythic-owned contract.

// Package wire defines Mythic's transport-independent custom crypto contract.
// Provider-owned cryptographic formats are opaque to this package.
package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

const (
	APIVersion        = 1
	MaxMessageBytes   = 64 << 20
	Describe          = "describe"
	PrepareProfile    = "prepare_profile"
	BeginSession      = "begin_session"
	Open              = "open"
	Seal              = "seal"
	GetOperation      = "get_operation"
	RevokeSession     = "revoke_session"
	OutcomeRejected   = "rejected"
	OutcomeUnresolved = "unresolved"
)

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// Capabilities are generic promises, not a description of native key formats.
type Capabilities struct {
	APIVersion             int      `json:"api_version"`
	Schemes                []string `json:"schemes"`
	Establishment          string   `json:"establishment"`
	SessionPersistence     string   `json:"session_persistence"`
	MaxMessageBytes        int      `json:"max_message_bytes"`
	ResultRetentionSeconds int      `json:"result_retention_seconds"`
}

func (c Capabilities) Validate() error {
	if c.APIVersion != APIVersion || c.Establishment != "single_round" {
		return errors.New("unsupported crypto provider API or establishment mode")
	}
	if c.SessionPersistence != "durable" && c.SessionPersistence != "volatile" {
		return errors.New("invalid crypto provider persistence mode")
	}
	if len(c.Schemes) == 0 || len(c.Schemes) > 128 || c.MaxMessageBytes < 1 || c.MaxMessageBytes > MaxMessageBytes || c.ResultRetentionSeconds < 1 {
		return errors.New("invalid crypto provider capabilities")
	}
	seen := map[string]bool{}
	for _, scheme := range c.Schemes {
		if !identifier.MatchString(scheme) || seen[scheme] {
			return errors.New("invalid or duplicate crypto scheme")
		}
		seen[scheme] = true
	}
	return nil
}

func (c Capabilities) Supports(scheme string) bool {
	for _, s := range c.Schemes {
		if s == scheme {
			return true
		}
	}
	return false
}

// Selection qualifies an external scheme so installing a worker cannot override
// built-in AES, none, or translation-container crypto implicitly.
func ParseSelection(value string) (name, scheme string, external bool, err error) {
	if !strings.HasPrefix(value, "provider:") {
		return "", "", false, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 3 || !identifier.MatchString(parts[1]) || !identifier.MatchString(parts[2]) {
		return "", "", true, errors.New("expected provider:<registered-name>:<scheme>")
	}
	return parts[1], parts[2], true, nil
}

// Request contains only application routing claims and opaque provider input.
// AuthContext is transient; it is excluded from the durable request digest.
type Request struct {
	APIVersion       int             `json:"api_version"`
	RequestID        string          `json:"request_id"`
	OperationScopeID int             `json:"operation_scope_id"`
	Method           string          `json:"method"`
	Scheme           string          `json:"scheme,omitempty"`
	ProfileRef       string          `json:"profile_ref,omitempty"`
	SessionRef       string          `json:"session_ref,omitempty"`
	Namespace        string          `json:"namespace,omitempty"`
	StateID          string          `json:"state_id,omitempty"`
	PayloadUUID      string          `json:"payload_uuid,omitempty"`
	NextUUID         string          `json:"next_uuid,omitempty"`
	Message          []byte          `json:"message,omitempty"`
	ProviderJSON     json.RawMessage `json:"provider_json,omitempty"`
	LookupRequestID  string          `json:"lookup_request_id,omitempty"`
	AuthContext      string          `json:"auth_context,omitempty"`
}

func (r Request) Validate() error {
	if r.APIVersion != APIVersion {
		return errors.New("unsupported crypto provider API version")
	}
	if id, err := uuid.Parse(r.RequestID); err != nil || id.String() != r.RequestID {
		return errors.New("invalid crypto request ID")
	}
	if r.OperationScopeID <= 0 {
		return errors.New("crypto operation scope is required")
	}
	if len(r.Message) > MaxMessageBytes || len(r.ProviderJSON) > MaxMessageBytes {
		return errors.New("crypto provider input exceeds limit")
	}
	if len(r.ProviderJSON) > 0 && !json.Valid(r.ProviderJSON) {
		return errors.New("invalid provider JSON")
	}
	switch r.Method {
	case Describe:
	case PrepareProfile:
		if !identifier.MatchString(r.Scheme) {
			return errors.New("crypto scheme is required")
		}
	case BeginSession:
		if r.ProfileRef == "" || len(r.Message) == 0 {
			return errors.New("profile and initial message are required")
		}
		for _, value := range []string{r.PayloadUUID, r.NextUUID} {
			if id, err := uuid.Parse(value); err != nil || id.String() != value {
				return errors.New("invalid crypto routing claim")
			}
		}
	case Open, Seal, RevokeSession:
		if r.SessionRef == "" || r.Namespace == "" {
			return errors.New("crypto session and namespace are required")
		}
	case GetOperation:
		if _, err := uuid.Parse(r.LookupRequestID); err != nil {
			return errors.New("invalid lookup request ID")
		}
	default:
		return errors.New("unknown crypto provider method")
	}
	for _, value := range []string{r.ProfileRef, r.SessionRef, r.Namespace, r.StateID} {
		if len(value) > 1024 {
			return errors.New("crypto reference exceeds limit")
		}
	}
	return nil
}

// Digest hashes the encoded request with transient authorization cleared.
// encoding/json compacts RawMessage whitespace; JSON member order and values
// still affect the encoding, so retries must preserve their original input.
func (r Request) Digest() (string, error) {
	r.AuthContext = ""
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type Failure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Rejected explicitly promises that this failure leaves no unresolved
	// cryptographic effect. Empty means unresolved for stateful operations.
	Outcome string `json:"outcome,omitempty"`
}

func (e *Failure) Error() string { return fmt.Sprintf("crypto provider: %s: %s", e.Code, e.Message) }

type Response struct {
	APIVersion       int             `json:"api_version"`
	RequestID        string          `json:"request_id"`
	OperationScopeID int             `json:"operation_scope_id"`
	Success          bool            `json:"success"`
	Error            *Failure        `json:"error,omitempty"`
	ProfileRef       string          `json:"profile_ref,omitempty"`
	SessionRef       string          `json:"session_ref,omitempty"`
	Namespace        string          `json:"namespace,omitempty"`
	StateID          string          `json:"state_id,omitempty"`
	Message          []byte          `json:"message,omitempty"`
	AgentConfig      []byte          `json:"agent_config,omitempty"`
	ProviderJSON     json.RawMessage `json:"provider_json,omitempty"`
	EncKey           *[]byte         `json:"enc_key,omitempty"`
	DecKey           *[]byte         `json:"dec_key,omitempty"`
	AuthContext      string          `json:"auth_context,omitempty"`
}

func (r Response) Validate(request Request) error {
	if r.APIVersion != APIVersion || r.RequestID != request.RequestID || r.OperationScopeID != request.OperationScopeID || r.AuthContext != request.AuthContext {
		return errors.New("mismatched crypto provider response")
	}
	if !r.Success {
		if r.Error == nil || r.Error.Code == "" {
			return errors.New("invalid crypto provider failure")
		}
		if r.Error.Outcome != "" && r.Error.Outcome != OutcomeRejected && r.Error.Outcome != OutcomeUnresolved {
			return errors.New("invalid crypto provider failure outcome")
		}
		return r.Error
	}
	if r.Error != nil {
		return errors.New("contradictory crypto provider response")
	}
	if len(r.Message) > MaxMessageBytes || len(r.AgentConfig) > MaxMessageBytes || len(r.ProviderJSON) > MaxMessageBytes {
		return errors.New("crypto provider response exceeds limit")
	}
	if len(r.ProviderJSON) > 0 && !json.Valid(r.ProviderJSON) {
		return errors.New("invalid provider response JSON")
	}
	for _, value := range []string{r.ProfileRef, r.SessionRef, r.Namespace, r.StateID} {
		if len(value) > 1024 {
			return errors.New("crypto response reference exceeds limit")
		}
	}
	if request.Method == PrepareProfile && r.ProfileRef == "" {
		return errors.New("provider omitted profile reference")
	}
	if request.Method == BeginSession && (r.SessionRef == "" || r.Namespace == "" || len(r.Message) == 0) {
		return errors.New("provider omitted established session or reply")
	}
	if request.Method == Open || request.Method == Seal || request.Method == RevokeSession {
		for _, identity := range [][2]string{
			{r.ProfileRef, request.ProfileRef},
			{r.SessionRef, request.SessionRef},
			{r.Namespace, request.Namespace},
			{r.StateID, request.StateID},
		} {
			if identity[0] != "" && identity[0] != identity[1] {
				return errors.New("mismatched crypto provider session")
			}
		}
	}
	return nil
}

func RoutingKey(name string) (string, error) {
	if !identifier.MatchString(name) {
		return "", errors.New("invalid crypto provider name")
	}
	return name + "_crypto_provider_rpc", nil
}
