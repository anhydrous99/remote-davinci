// Package protocol validates Remote DaVinci v1 wire messages at trust boundaries.
package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
)

const (
	ProtocolName                       = "remote-davinci.rendezvous"
	ProtocolVersion              int64 = 1
	ControlProtocolName                = "remote-davinci.control"
	ControlProtocolVersion             = 1
	PairingProtocolName                = "remote-davinci.pairing"
	PairingProtocolVersion             = 1
	PairingInviteProtocolName          = "remote-davinci.pairing-invite"
	PairingInviteProtocolVersion       = 1
	PairingAuthorization               = "Pairing rd1"
	PairingAppID                       = "remote-davinci/pair/v1"
	PairingNoiseProtocol               = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
	PairingNoisePrefix                 = "remote-davinci/pair-qr/v1"
	SessionNoiseProtocol               = "Noise_IK_25519_ChaChaPoly_SHA256"
	SessionNoisePrefix                 = "remote-davinci/session/v1"

	MaxWebSocketFrameBytes   = 32 * 1024
	MaxRelayPayloadBytes     = 16 * 1024
	MaxRelayReorderFrames    = 8
	MaxRelayReorderBytes     = MaxRelayPayloadBytes * MaxRelayReorderFrames
	MaxControlPlaintextBytes = MaxRelayPayloadBytes - 16
	MaxPairingPlaintextBytes = (MaxRelayPayloadBytes-23)/2 - 40
	MaxPairingInviteBytes    = 2 * 1024
	PairingTTLSeconds        = 5 * 60
	LocatorDigits            = 6
	PairingWords             = 4
)

var (
	ClientMessageTypes = []string{
		"system.hello", "system.ping", "pair.create", "pair.join", "pair.commit",
		"pair.cancel", "pair.frame", "link.get", "link.revoke", "endpoint.rotate",
		"endpoint.revoke", "session.open", "session.close", "session.frame",
	}
	ServerMessageTypes = []string{
		"ok", "error", "pair.ready", "pair.completed", "pair.closed", "pair.frame",
		"session.opened", "session.closed", "session.frame", "link.revoked",
	}
	ControlMessageTypes = []string{"hello", "request", "response", "event"}
	ErrorCodes          = []ErrorCode{
		InvalidMessage, UnsupportedVersion, Unauthenticated, Forbidden, PairUnavailable,
		PairFull, PairExpired, PeerOffline, PeerBusy, SessionNotFound, PayloadTooLarge,
		RateLimited, Conflict, Internal,
	}
)

type ErrorCode string

const (
	InvalidMessage     ErrorCode = "INVALID_MESSAGE"
	UnsupportedVersion ErrorCode = "UNSUPPORTED_VERSION"
	Unauthenticated    ErrorCode = "UNAUTHENTICATED"
	Forbidden          ErrorCode = "FORBIDDEN"
	PairUnavailable    ErrorCode = "PAIR_UNAVAILABLE"
	PairFull           ErrorCode = "PAIR_FULL"
	PairExpired        ErrorCode = "PAIR_EXPIRED"
	PeerOffline        ErrorCode = "PEER_OFFLINE"
	PeerBusy           ErrorCode = "PEER_BUSY"
	SessionNotFound    ErrorCode = "SESSION_NOT_FOUND"
	PayloadTooLarge    ErrorCode = "PAYLOAD_TOO_LARGE"
	RateLimited        ErrorCode = "RATE_LIMITED"
	Conflict           ErrorCode = "CONFLICT"
	Internal           ErrorCode = "INTERNAL"
)

type DeviceRole string

const (
	Controller DeviceRole = "controller"
	Companion  DeviceRole = "companion"
)

type Envelope struct {
	Protocol string          `json:"protocol"`
	V        int64           `json:"v"`
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	ReplyTo  string          `json:"replyTo,omitempty"`
	Body     json.RawMessage `json:"body"`
}

type ClientEnvelope = Envelope
type ServerEnvelope = Envelope
type RendezvousEnvelope = Envelope
type ControlEnvelope = Envelope

type JSONValue = any
type JSONObject map[string]any
type EmptyBody = JSONObject

type SystemPingBody struct {
	SentAt int64 `json:"sentAt"`
}

type PairCreateBody struct {
	JoinTokenHash string `json:"joinTokenHash,omitempty"`
}

type PairJoinBody struct {
	Locator   string `json:"locator,omitempty"`
	JoinToken string `json:"joinToken,omitempty"`
}

type PairingInvite struct {
	Protocol      string `json:"protocol"`
	V             int64  `json:"v"`
	RelayURL      string `json:"relayUrl"`
	PairID        string `json:"pairId"`
	CreatorSideID string `json:"creatorSideId"`
	LinkID        string `json:"linkId"`
	JoinToken     string `json:"joinToken"`
	PSK           string `json:"psk"`
	ExpiresAt     int64  `json:"expiresAt"`
}

type PairCancelBody struct {
	PairID string `json:"pairId"`
}

type LinkBody struct {
	LinkID string `json:"linkId"`
}

type EndpointRotateBody struct {
	CredentialHash string `json:"credentialHash"`
}

type SessionCloseBody struct {
	SessionID string `json:"sessionId"`
}

type RoutingEndpoint struct {
	EndpointID string     `json:"endpointId"`
	Role       DeviceRole `json:"role"`
}

type EndpointCommit struct {
	EndpointID     string     `json:"endpointId"`
	Role           DeviceRole `json:"role"`
	CredentialHash string     `json:"credentialHash"`
}

type PairCommitBody struct {
	PairID string          `json:"pairId"`
	SideID string          `json:"sideId"`
	LinkID string          `json:"linkId"`
	Self   EndpointCommit  `json:"self"`
	Peer   RoutingEndpoint `json:"peer"`
}

type PairFrameBody struct {
	PairID  string `json:"pairId"`
	Seq     int64  `json:"seq"`
	Payload string `json:"payload"`
}

type SessionFrameBody struct {
	SessionID string `json:"sessionId"`
	Seq       int64  `json:"seq"`
	Payload   string `json:"payload"`
}

type PairingIdentityBody struct {
	LinkID           string     `json:"linkId"`
	EndpointID       string     `json:"endpointId"`
	Role             DeviceRole `json:"role"`
	NoiseKey         string     `json:"noiseKey"`
	NoiseFingerprint string     `json:"noiseFingerprint"`
	DeviceLabel      string     `json:"deviceLabel"`
	Permissions      []string   `json:"permissions"`
	Capabilities     []string   `json:"capabilities"`
}

type PairingIdentityEnvelope struct {
	Protocol string              `json:"protocol"`
	V        int64               `json:"v"`
	Type     string              `json:"type"`
	ID       string              `json:"id"`
	Body     PairingIdentityBody `json:"body"`
}

type WormholeMessage struct {
	Phase string `json:"phase"`
	Body  string `json:"body"`
}

type ControlHelloBody struct {
	Role         DeviceRole `json:"role"`
	Capabilities []string   `json:"capabilities"`
	AppVersion   string     `json:"appVersion"`
}

type ControlRequestBody struct {
	Operation string     `json:"operation"`
	Args      JSONObject `json:"args"`
	SentAt    int64      `json:"sentAt"`
	ExpiresAt int64      `json:"expiresAt"`
}

type ControlError struct {
	Code      string `json:"code"`
	Message   string `json:"message,omitempty"`
	Retryable *bool  `json:"retryable,omitempty"`
}

type ControlSuccessBody struct {
	OK     bool      `json:"ok"`
	Result JSONValue `json:"result"`
}

type ControlFailureBody struct {
	OK    bool         `json:"ok"`
	Error ControlError `json:"error"`
}

type ControlEventBody struct {
	Name string    `json:"name"`
	Data JSONValue `json:"data"`
}

type ParsedAuthorization struct {
	Scheme     string `json:"scheme"`
	EndpointID string `json:"endpointId,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

type ValidationError struct {
	Code    ErrorCode
	Message string
	Issues  []string
}

func (e *ValidationError) Error() string { return e.Message }

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	bearerPattern = regexp.MustCompile(`^Bearer rd1\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$`)
)

func SessionNoisePrologue(linkID, sessionID string) ([]byte, error) {
	if !uuidPattern.MatchString(linkID) || !uuidPattern.MatchString(sessionID) {
		return nil, validationError(InvalidMessage, "Noise prologue IDs must be lowercase UUIDs")
	}
	return []byte(SessionNoisePrefix + "\n" + linkID + "\n" + sessionID), nil
}

func PairingNoisePrologue(relayURL, pairID, creatorSideID, joinerSideID, linkID string, expiresAt int64) ([]byte, error) {
	if !validRelayURL(relayURL) ||
		!uuidPattern.MatchString(pairID) || !uuidPattern.MatchString(creatorSideID) ||
		!uuidPattern.MatchString(joinerSideID) || !uuidPattern.MatchString(linkID) ||
		expiresAt < 0 || expiresAt > 253402300799 {
		return nil, validationError(InvalidMessage, "Pairing Noise prologue fields are invalid")
	}
	return []byte(PairingNoisePrefix + "\n" + relayURL + "\n" + pairID + "\n" + creatorSideID + "\n" + joinerSideID + "\n" + linkID + "\n" + strconv.FormatInt(expiresAt, 10)), nil
}

func JoinTokenHash(joinToken string) (string, error) {
	token, ok := canonicalBase64URL(joinToken)
	if !ok || len(token) != 32 {
		return "", validationError(InvalidMessage, "Join token must be 32 canonical base64url bytes")
	}
	digest := sha256.Sum256(token)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func ValidatePairingInviteAt(invite PairingInvite, now int64) error {
	if _, err := ParsePairingInvite(invite); err != nil {
		return err
	}
	if now < 0 || invite.ExpiresAt <= now || invite.ExpiresAt-now > PairingTTLSeconds {
		return validationError(PairExpired, "Pairing invite is expired or outside its lifetime")
	}
	return nil
}

func NoiseKeyFingerprint(noiseKey string) (string, error) {
	key, ok := canonicalBase64URL(noiseKey)
	if !ok || len(key) != 32 {
		return "", validationError(InvalidMessage, "Noise public key must be 32 canonical base64url bytes")
	}
	digest := sha256.Sum256(key)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func ParseAuthorization(header string) (ParsedAuthorization, error) {
	if header == PairingAuthorization {
		return ParsedAuthorization{Scheme: "pairing"}, nil
	}
	match := bearerPattern.FindStringSubmatch(header)
	if len(match) != 3 {
		return ParsedAuthorization{}, validationError(Unauthenticated, "Authorization header is missing or invalid")
	}
	secret, ok := canonicalBase64URL(match[2])
	if !ok || len(secret) != 32 {
		return ParsedAuthorization{}, validationError(Unauthenticated, "Authorization header is missing or invalid")
	}
	return ParsedAuthorization{Scheme: "bearer", EndpointID: match[1], Secret: match[2]}, nil
}

func canonicalBase64URL(value string) ([]byte, bool) {
	if value == "" || len(value)%4 == 1 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func validRelayURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "wss" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validationError(code ErrorCode, message string, issues ...string) *ValidationError {
	return &ValidationError{Code: code, Message: message, Issues: issues}
}

func (e Envelope) DecodeBody(target any) error {
	if err := json.Unmarshal(e.Body, target); err != nil {
		return fmt.Errorf("decode validated %s body: %w", e.Type, err)
	}
	return nil
}
