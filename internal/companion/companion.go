package companion

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	DefaultRelayURL          = "wss://t25ft375dj.execute-api.us-east-1.amazonaws.com/v1"
	maxFrameBytes            = protocol.MaxWebSocketFrameBytes
	maxPendingRelayResponses = 32
	maxPendingRelayWireBytes = protocol.MaxWebSocketFrameBytes * protocol.MaxRelayReorderFrames
	relayRequestTimeout      = 15 * time.Second
)

var Version = "0.1.0"

const allPermissionBits uint8 = 1<<8 - 1

var supportedOperations = []string{
	"resolve.page.cut",
	"resolve.page.edit",
	"resolve.page.fusion",
	"resolve.page.color",
	"host.volume.toggle-mute",
	// Keep new operations after the original five so stored permission bits stay stable.
	"resolve.page.media",
	"resolve.page.fairlight",
	"resolve.page.deliver",
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var x25519ValidationPrivate = [32]byte{1}

type EnrollmentRequest struct {
	V                        int    `json:"v"`
	ControllerEndpointID     string `json:"controllerEndpointId"`
	ControllerCredentialHash string `json:"controllerCredentialHash"`
	ControllerNoiseKey       string `json:"controllerNoiseKey"`
	DeviceLabel              string `json:"deviceLabel"`
}

type EnrollmentResponse struct {
	V                    int    `json:"v"`
	RelayURL             string `json:"relayUrl"`
	LinkID               string `json:"linkId"`
	ControllerEndpointID string `json:"controllerEndpointId"`
	CompanionEndpointID  string `json:"companionEndpointId"`
	CompanionNoiseKey    string `json:"companionNoiseKey"`
	Warning              string `json:"warning,omitempty"`
}

type Config struct {
	V                     int    `json:"v"`
	RelayURL              string `json:"relayUrl"`
	LinkID                string `json:"linkId"`
	EndpointID            string `json:"endpointId"`
	Secret                string `json:"secret"`
	NoisePrivateKey       string `json:"noisePrivateKey"`
	ControllerEndpointID  string `json:"controllerEndpointId"`
	ControllerNoiseKey    string `json:"controllerNoiseKey"`
	ControllerFingerprint string `json:"controllerFingerprint,omitempty"`
	ControllerLabel       string `json:"controllerLabel"`
	PermissionMask        uint8  `json:"permissionMask,omitempty"`
	ActivationPending     bool   `json:"activationPending,omitempty"`
	LinkRevoked           bool   `json:"linkRevoked,omitempty"`
}

func manualEnrollmentResponse(config Config) (EnrollmentResponse, error) {
	privateKey, err := decode32(config.NoisePrivateKey)
	if err != nil {
		return EnrollmentResponse{}, err
	}
	keypair, err := noise.DH25519.GenerateKeypair(bytes.NewReader(privateKey))
	if err != nil {
		return EnrollmentResponse{}, err
	}
	return EnrollmentResponse{
		V: config.V, RelayURL: config.RelayURL, LinkID: config.LinkID,
		ControllerEndpointID: config.ControllerEndpointID,
		CompanionEndpointID:  config.EndpointID,
		CompanionNoiseKey:    base64.RawURLEncoding.EncodeToString(keypair.Public),
	}, nil
}

func (config Config) validate() error {
	if config.V != 1 || !uuidPattern.MatchString(config.LinkID) || !uuidPattern.MatchString(config.EndpointID) ||
		!uuidPattern.MatchString(config.ControllerEndpointID) {
		return errors.New("invalid companion configuration")
	}
	if _, err := relayURL(config.RelayURL); err != nil {
		return err
	}
	secret, err := decode32(config.Secret)
	if err != nil {
		return errors.New("invalid companion configuration")
	}
	privateKey, err := decode32(config.NoisePrivateKey)
	if err != nil {
		return errors.New("invalid companion configuration")
	}
	controllerKey, err := decode32(config.ControllerNoiseKey)
	if err != nil || !contributoryX25519PublicKey(controllerKey, privateKey) {
		return errors.New("invalid companion configuration")
	}
	if config.ControllerFingerprint != "" {
		fingerprint, err := protocol.NoiseKeyFingerprint(config.ControllerNoiseKey)
		if err != nil || fingerprint != config.ControllerFingerprint {
			return errors.New("invalid companion configuration")
		}
	}
	if config.PermissionMask&^allPermissionBits != 0 {
		return errors.New("invalid companion configuration")
	}
	if len(secret) != 32 {
		return errors.New("invalid companion configuration")
	}
	return nil
}

func contributoryX25519PublicKey(publicKey, privateKey []byte) bool {
	private, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return false
	}
	public, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return false
	}
	_, err = private.ECDH(public)
	return err == nil
}

func validateEnrollment(request EnrollmentRequest) error {
	if request.V != 1 || !uuidPattern.MatchString(request.ControllerEndpointID) ||
		utf8.RuneCountInString(request.DeviceLabel) < 1 || utf8.RuneCountInString(request.DeviceLabel) > 80 {
		return errors.New("invalid enrollment request")
	}
	if _, err := decode32(request.ControllerCredentialHash); err != nil {
		return errors.New("invalid enrollment request")
	}
	key, err := decode32(request.ControllerNoiseKey)
	if err != nil {
		return errors.New("invalid enrollment request")
	}
	if !contributoryX25519PublicKey(key, x25519ValidationPrivate[:]) {
		return errors.New("invalid enrollment request")
	}
	return nil
}

func ParseEnrollmentRequest(data []byte) (EnrollmentRequest, error) {
	if len(data) > 16*1024 {
		return EnrollmentRequest{}, errors.New("enrollment request is too large")
	}
	var request EnrollmentRequest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return EnrollmentRequest{}, errors.New("invalid enrollment request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return EnrollmentRequest{}, errors.New("invalid enrollment request")
	}
	if err := validateEnrollment(request); err != nil {
		return EnrollmentRequest{}, err
	}
	return request, nil
}

func relayURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("relay URL must be a credential-free wss URL")
	}
	return parsed, nil
}

func decode32(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("value must be 32 canonical base64url bytes")
	}
	return decoded, nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:]), nil
}

func random32() ([]byte, error) {
	value := make([]byte, 32)
	_, err := rand.Read(value)
	return value, err
}

func noiseKeypair() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

type wireEnvelope struct {
	Protocol string `json:"protocol"`
	V        int64  `json:"v"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Body     any    `json:"body"`
}

type relayPeer struct {
	connection   *websocket.Conn
	pending      []json.RawMessage
	pendingBytes int
}

type relayUpgradeError struct{ status int }

func (failure *relayUpgradeError) Error() string {
	return fmt.Sprintf("relay WebSocket upgrade failed with status %d", failure.status)
}

type relayResponseError struct {
	requestType string
	code        protocol.ErrorCode
}

func (failure *relayResponseError) Error() string {
	return fmt.Sprintf("relay rejected %s: %s", failure.requestType, failure.code)
}

var errConfigPersistence = errors.New("could not persist companion credentials")

func dialRelay(ctx context.Context, relay, authorization string) (*relayPeer, error) {
	header := http.Header{}
	header.Set("Authorization", authorization)
	connection, response, err := websocket.Dial(ctx, relay, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if response != nil {
			return nil, &relayUpgradeError{status: response.StatusCode}
		}
		return nil, fmt.Errorf("relay WebSocket upgrade failed: %w", err)
	}
	connection.SetReadLimit(maxFrameBytes)
	return &relayPeer{connection: connection}, nil
}

func (peer *relayPeer) close() {
	_ = peer.connection.Close(websocket.StatusNormalClosure, "done")
}

func (peer *relayPeer) request(ctx context.Context, messageType string, body any, result any) error {
	ctx, cancel := context.WithTimeout(ctx, relayRequestTimeout)
	defer cancel()

	id, err := randomUUID()
	if err != nil {
		return err
	}
	message := wireEnvelope{Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType, ID: id, Body: body}
	if err := wsjson.Write(ctx, peer.connection, message); err != nil {
		return err
	}
	for {
		var raw json.RawMessage
		if err := wsjson.Read(ctx, peer.connection, &raw); err != nil {
			return err
		}
		envelope, err := protocol.ParseServer(raw)
		if err != nil {
			return errors.New("relay returned an invalid response")
		}
		if envelope.ReplyTo != id {
			if err := peer.queuePending(raw); err != nil {
				return err
			}
			continue
		}
		if envelope.Type == "error" {
			var failure struct {
				Code string `json:"code"`
			}
			_ = envelope.DecodeBody(&failure)
			if failure.Code == "" {
				failure.Code = string(protocol.Internal)
			}
			return &relayResponseError{requestType: messageType, code: protocol.ErrorCode(failure.Code)}
		}
		var success struct {
			RequestType string          `json:"requestType"`
			Result      json.RawMessage `json:"result"`
		}
		if envelope.Type != "ok" || envelope.DecodeBody(&success) != nil || success.RequestType != messageType {
			return errors.New("relay returned an invalid response")
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(success.Result, result)
	}
}

func (peer *relayPeer) queuePending(raw json.RawMessage) error {
	// pendingBytes counts complete on-wire JSON WebSocket message bytes. Keep it
	// separate from the decoded payload-byte limit used by session reordering.
	if len(peer.pending) >= maxPendingRelayResponses || peer.pendingBytes+len(raw) > maxPendingRelayWireBytes {
		return errors.New("relay returned too many unmatched responses")
	}
	peer.pending = append(peer.pending, append(json.RawMessage(nil), raw...))
	peer.pendingBytes += len(raw)
	return nil
}

// RevokeEnrollment checkpoints the irreversible link revocation before making
// endpoint revocation best effort. The caller must stop its active relay first.
func RevokeEnrollment(ctx context.Context, config Config, persist func(Config) error) error {
	if err := config.validate(); err != nil {
		return err
	}
	if persist == nil {
		return errors.New("revocation checkpoint is required")
	}
	peer, err := dialRelay(ctx, config.RelayURL, "Bearer rd1."+config.EndpointID+"."+config.Secret)
	if err != nil {
		if config.LinkRevoked {
			return nil
		}
		var upgrade *relayUpgradeError
		if config.ActivationPending && errors.As(err, &upgrade) && upgrade.status == http.StatusUnauthorized {
			// Pair activation creates the endpoint and link atomically. A strongly
			// consistent 401 therefore proves this uncertain activation left no
			// usable link, or that its endpoint was since revoked.
			config.LinkRevoked = true
			if err := persist(config); err != nil {
				return fmt.Errorf("%w: %v", errConfigPersistence, err)
			}
			return nil
		}
		return err
	}
	defer peer.close()

	if !config.LinkRevoked {
		var link struct {
			Revoked bool `json:"revoked"`
		}
		if err := peer.request(ctx, "link.revoke", protocol.LinkBody{LinkID: config.LinkID}, &link); err != nil {
			return err
		}
		if !link.Revoked {
			return errors.New("relay did not acknowledge link revocation")
		}
		config.LinkRevoked = true
		if err := persist(config); err != nil {
			return fmt.Errorf("%w: %v", errConfigPersistence, err)
		}
	}
	var endpoint struct {
		Revoked bool `json:"revoked"`
	}
	// The durable link checkpoint makes an endpoint ack or reconnect unnecessary
	// for safe local deletion; still ask the relay to revoke it when reachable.
	_ = peer.request(ctx, "endpoint.revoke", map[string]any{}, &endpoint)
	return nil
}

// Provision uses the existing relay pairing records as an administrative bridge.
// ponytail: the two-way manual transfer is the trusted onboarding channel; add
// the documented PAKE/QR ceremony before onboarding anyone outside one operator.
func Provision(ctx context.Context, relay string, request EnrollmentRequest, persistence ...func(Config) error) (Config, EnrollmentResponse, error) {
	if len(persistence) > 1 || len(persistence) == 1 && persistence[0] == nil {
		return Config{}, EnrollmentResponse{}, errors.New("invalid configuration persistence callback")
	}
	if _, err := relayURL(relay); err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	if err := validateEnrollment(request); err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	companionEndpointID, err := randomUUID()
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	linkID, err := randomUUID()
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	secret, err := random32()
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	keypair, err := noiseKeypair()
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	secretDigest := sha256.Sum256(secret)

	creator, err := dialRelay(ctx, relay, protocol.PairingAuthorization)
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	defer creator.close()
	var created struct {
		PairID    string `json:"pairId"`
		SideID    string `json:"sideId"`
		Locator   string `json:"locator"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := creator.request(ctx, "pair.create", map[string]any{}, &created); err != nil {
		return Config{}, EnrollmentResponse{}, err
	}

	joiner, err := dialRelay(ctx, relay, protocol.PairingAuthorization)
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	defer joiner.close()
	var joined struct {
		PairID string `json:"pairId"`
		SideID string `json:"sideId"`
	}
	if err := joiner.request(ctx, "pair.join", map[string]any{"locator": created.Locator}, &joined); err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	if joined.PairID != created.PairID {
		return Config{}, EnrollmentResponse{}, errors.New("relay paired mismatched records")
	}

	companionCommit := protocol.PairCommitBody{
		PairID: created.PairID, SideID: created.SideID, LinkID: linkID,
		Self: protocol.EndpointCommit{
			EndpointID: companionEndpointID, Role: protocol.Companion,
			CredentialHash: base64.RawURLEncoding.EncodeToString(secretDigest[:]),
		},
		Peer: protocol.RoutingEndpoint{EndpointID: request.ControllerEndpointID, Role: protocol.Controller},
	}
	controllerCommit := protocol.PairCommitBody{
		PairID: created.PairID, SideID: joined.SideID, LinkID: linkID,
		Self: protocol.EndpointCommit{
			EndpointID: request.ControllerEndpointID, Role: protocol.Controller,
			CredentialHash: request.ControllerCredentialHash,
		},
		Peer: protocol.RoutingEndpoint{EndpointID: companionEndpointID, Role: protocol.Companion},
	}
	config := Config{
		V: 1, RelayURL: relay, LinkID: linkID, EndpointID: companionEndpointID,
		Secret:               base64.RawURLEncoding.EncodeToString(secret),
		NoisePrivateKey:      base64.RawURLEncoding.EncodeToString(keypair.Private),
		ControllerEndpointID: request.ControllerEndpointID,
		ControllerNoiseKey:   request.ControllerNoiseKey,
		ControllerLabel:      request.DeviceLabel,
	}
	response, err := manualEnrollmentResponse(config)
	if err != nil {
		return Config{}, EnrollmentResponse{}, err
	}
	var pending struct {
		Pending bool `json:"pending"`
	}
	if err := creator.request(ctx, "pair.commit", companionCommit, &pending); err != nil || !pending.Pending {
		if err == nil {
			err = errors.New("relay did not hold the first pairing commit")
		}
		return Config{}, EnrollmentResponse{}, err
	}
	if len(persistence) == 1 {
		config.ActivationPending = true
		if err := persistence[0](config); err != nil {
			return Config{}, EnrollmentResponse{}, fmt.Errorf("%w: %v", errConfigPersistence, err)
		}
	}
	var active struct {
		LinkID string `json:"linkId"`
		Active bool   `json:"active"`
	}
	if err := joiner.request(ctx, "pair.commit", controllerCommit, &active); err != nil || !active.Active || active.LinkID != linkID {
		if err == nil {
			err = errors.New("relay did not activate the link")
		}
		return config, response, err
	}
	if len(persistence) == 1 {
		config.ActivationPending = false
		if err := persistence[0](config); err != nil {
			config.ActivationPending = true
			return config, response, fmt.Errorf("%w after relay activation: %v", errConfigPersistence, err)
		}
	}
	return config, response, nil
}

type operationError struct {
	code string
}

func (failure *operationError) Error() string { return failure.code }

type commandOutput func(context.Context, string, ...string) ([]byte, error)

func ExecuteOperation(ctx context.Context, operation string) (map[string]any, error) {
	return executeOperation(ctx, operation, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	})
}

func executeOperation(ctx context.Context, operation string, output commandOutput) (map[string]any, error) {
	commandContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if page, ok := resolvePageForOperation(operation); ok {
		const script = `import sys
sys.path.insert(0, "/Library/Application Support/Blackmagic Design/DaVinci Resolve/Developer/Scripting/Modules")
import DaVinciResolveScript as dvr
requested = sys.argv[1]
resolve = dvr.scriptapp("Resolve")
if resolve is None:
    raise SystemExit(20)
current = resolve.GetCurrentPage()
if current != requested:
    if not resolve.OpenPage(requested):
        raise SystemExit(21)
    current = resolve.GetCurrentPage()
print(current or "")
`
		readback, err := output(commandContext, "/usr/bin/python3", "-I", "-c", script, page)
		if err != nil || strings.TrimSpace(string(readback)) != page {
			return nil, &operationError{code: "resolve.unavailable"}
		}
		return map[string]any{"page": page}, nil
	}
	switch operation {
	case "host.volume.toggle-mute":
		const script = `set currentSettings to get volume settings
try
    set currentMuted to output muted of currentSettings
on error
    return "unsupported"
end try
if currentMuted is missing value then return "unsupported"
set volume output muted not currentMuted
return output muted of (get volume settings)`
		result, err := output(commandContext, "/usr/bin/osascript", "-e", script)
		return parseMuteResult(result, err)
	default:
		return nil, &operationError{code: "operation.unsupported"}
	}
}

func resolvePageForOperation(operation string) (string, bool) {
	switch operation {
	case "resolve.page.media", "resolve.page.cut", "resolve.page.edit", "resolve.page.fusion",
		"resolve.page.color", "resolve.page.fairlight", "resolve.page.deliver":
		return strings.TrimPrefix(operation, "resolve.page."), true
	default:
		return "", false
	}
}

func supportedResolvePage(page string) bool {
	_, ok := resolvePageForOperation("resolve.page." + page)
	return ok
}

type resolvePageObservation struct {
	page       string
	observedAt time.Time
}

type resolvePageMonitorRun func(context.Context, func(resolvePageObservation) error) error

// ponytail: Resolve exposes no page-change callback; replace this 500 ms poll only if the SDK adds one.
const resolvePageMonitorScript = `import sys
import time
sys.path.insert(0, "/Library/Application Support/Blackmagic Design/DaVinci Resolve/Developer/Scripting/Modules")
import DaVinciResolveScript as dvr
resolve = None
while True:
    observed_at = time.time_ns()
    try:
        if resolve is None:
            resolve = dvr.scriptapp("Resolve")
        page = resolve.GetCurrentPage() if resolve is not None else None
        if page is None:
            resolve = None
    except Exception:
        resolve = None
        page = None
    print(f"{observed_at}\t{page or '-'}", flush=True)
    time.sleep(0.5)
`

func monitorResolvePages(ctx context.Context, run resolvePageMonitorRun) <-chan resolvePageObservation {
	pages := make(chan resolvePageObservation)
	go func() {
		defer close(pages)
		var retryDelay time.Duration
		for ctx.Err() == nil {
			observed := false
			_ = run(ctx, func(observation resolvePageObservation) error {
				select {
				case pages <- observation:
					observed = true
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			if ctx.Err() != nil {
				return
			}
			retryDelay = resolvePageMonitorRetryDelay(retryDelay, observed)
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return pages
}

func resolvePageMonitorRetryDelay(previous time.Duration, observed bool) time.Duration {
	if observed || previous == 0 {
		return time.Second
	}
	return min(previous*2, 15*time.Minute)
}

func runResolvePageMonitor(ctx context.Context, emit func(resolvePageObservation) error) error {
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-u", "-c", resolvePageMonitorScript)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		observation, err := parseResolvePageObservation(scanner.Text())
		if err == nil {
			err = emit(observation)
		}
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
	}
	scanErr := scanner.Err()
	waitErr := command.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return scanErr
	}
	return waitErr
}

func parseResolvePageObservation(line string) (resolvePageObservation, error) {
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		return resolvePageObservation{}, errors.New("invalid Resolve page observation")
	}
	nanoseconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || nanoseconds <= 0 || strings.TrimSpace(parts[1]) == "" {
		return resolvePageObservation{}, errors.New("invalid Resolve page observation")
	}
	return resolvePageObservation{page: strings.TrimSpace(parts[1]), observedAt: time.Unix(0, nanoseconds)}, nil
}

func parseMuteResult(output []byte, commandErr error) (map[string]any, error) {
	if commandErr != nil {
		return nil, &operationError{code: "host.control-failed"}
	}
	switch strings.TrimSpace(string(output)) {
	case "unsupported":
		return nil, &operationError{code: "host.mute-unsupported"}
	case "true":
		return map[string]any{"muted": true}, nil
	case "false":
		return map[string]any{"muted": false}, nil
	default:
		return nil, &operationError{code: "host.control-failed"}
	}
}

type controlProcessor struct {
	now       func() time.Time
	execute   func(context.Context, string) (map[string]any, error)
	allowed   map[string]bool
	peerHello bool
	cache     map[string][]byte
}

func newControlProcessor(execute func(context.Context, string) (map[string]any, error), permissions ...[]string) *controlProcessor {
	granted := supportedOperations
	if len(permissions) == 1 {
		granted = permissions[0]
	}
	allowed := make(map[string]bool, len(granted))
	for _, operation := range granted {
		allowed[operation] = true
	}
	return &controlProcessor{now: time.Now, execute: execute, allowed: allowed, cache: make(map[string][]byte)}
}

func (processor *controlProcessor) handle(ctx context.Context, plaintext []byte) ([]byte, bool, error) {
	envelope, err := protocol.ParseControl(plaintext)
	if err != nil {
		return nil, false, err
	}
	switch envelope.Type {
	case "hello":
		var body protocol.ControlHelloBody
		if processor.peerHello || envelope.DecodeBody(&body) != nil || body.Role != protocol.Controller {
			return nil, false, errors.New("unexpected control hello")
		}
		processor.peerHello = true
		return nil, false, nil
	case "request":
		if cached := processor.cache[envelope.ID]; cached != nil {
			return cached, true, nil
		}
		if len(processor.cache) >= 256 {
			return nil, false, errors.New("session request limit reached")
		}
		var body protocol.ControlRequestBody
		if err := envelope.DecodeBody(&body); err != nil {
			return nil, false, err
		}
		if !processor.peerHello {
			return nil, false, errors.New("control hello must be first")
		}
		now := processor.now().UnixMilli()
		if body.ExpiresAt <= now || body.SentAt > now+30_000 || len(body.Args) != 0 {
			return processor.response(envelope.ID, nil, &operationError{code: "request.invalid"})
		}
		if !processor.allowed[body.Operation] {
			return processor.response(envelope.ID, nil, &operationError{code: "operation.forbidden"})
		}
		result, executeErr := processor.execute(ctx, body.Operation)
		return processor.response(envelope.ID, result, executeErr)
	default:
		return nil, false, errors.New("unexpected control message")
	}
}

func (processor *controlProcessor) response(replyTo string, result map[string]any, failure error) ([]byte, bool, error) {
	id, err := randomUUID()
	if err != nil {
		return nil, false, err
	}
	body := map[string]any{"ok": true, "result": result}
	if failure != nil {
		code := "operation.failed"
		var operationFailure *operationError
		if errors.As(failure, &operationFailure) {
			code = operationFailure.code
		}
		body = map[string]any{"ok": false, "error": map[string]any{"code": code, "retryable": false}}
	}
	message := struct {
		Protocol string         `json:"protocol"`
		V        int64          `json:"v"`
		Type     string         `json:"type"`
		ID       string         `json:"id"`
		ReplyTo  string         `json:"replyTo"`
		Body     map[string]any `json:"body"`
	}{protocol.ControlProtocolName, protocol.ControlProtocolVersion, "response", id, replyTo, body}
	data, err := json.Marshal(message)
	if err != nil {
		return nil, false, err
	}
	processor.cache[replyTo] = data
	return data, true, nil
}

func controlHello() ([]byte, error) {
	id, err := randomUUID()
	if err != nil {
		return nil, err
	}
	return json.Marshal(wireEnvelope{
		Protocol: protocol.ControlProtocolName, V: protocol.ControlProtocolVersion, Type: "hello", ID: id,
		Body: protocol.ControlHelloBody{
			Role: protocol.Companion, Capabilities: append([]string(nil), supportedOperations...), AppVersion: Version,
		},
	})
}

func grantedPermissions(mask uint8) []string {
	if mask == 0 { // Legacy enrollment granted every v1 operation.
		mask = allPermissionBits
	}
	permissions := make([]string, 0, len(supportedOperations))
	for index, operation := range supportedOperations {
		if mask&(1<<index) != 0 {
			permissions = append(permissions, operation)
		}
	}
	return permissions
}

func requestedPermissionMask(requested []string) uint8 {
	var mask uint8
	for index, supported := range supportedOperations {
		for _, operation := range requested {
			if operation == supported {
				mask |= 1 << index
				break
			}
		}
	}
	return mask
}
