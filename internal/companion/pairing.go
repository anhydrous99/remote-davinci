package companion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	pairingShowingQR        = "showingQR"
	pairingHandshaking      = "handshaking"
	pairingAwaitingApproval = "awaitingApproval"
	pairingCommitting       = "committing"
	pairingExpired          = "expired"
	pairingCancelled        = "cancelled"
	pairingRejected         = "rejected"
	pairingFailed           = "failed"
)

var (
	errPairingCancelled      = errors.New("QR pairing was cancelled")
	errPairingRejected       = errors.New("QR pairing was rejected")
	errPairingCommitRejected = errors.New("relay rejected the pairing commit")
)

type PairingState struct {
	Phase                 string   `json:"phase"`
	PairID                string   `json:"pairId,omitempty"`
	ExpiresAt             int64    `json:"expiresAt,omitempty"`
	ControllerLabel       string   `json:"controllerLabel,omitempty"`
	ControllerFingerprint string   `json:"controllerFingerprint,omitempty"`
	RequestedPermissions  []string `json:"requestedPermissions,omitempty"`
}

type pairingAttempt struct {
	ctx          context.Context
	cancel       context.CancelFunc
	peer         *relayPeer
	invite       protocol.PairingInvite
	label        string
	persist      func(Config) error
	discard      func() error
	decision     chan bool
	decided      bool
	done         chan struct{}
	mu           sync.RWMutex
	state        PairingState
	endpoint     string
	secret       []byte
	noiseKeys    noise.DHKey
	activated    bool
	nextIn       int64
	pending      map[int64][]byte
	pendingBytes int
}

func newPairingAttempt(parent, setup context.Context, relay, label string, persist func(Config) error, discard func() error) (*pairingAttempt, error) {
	if persist == nil || discard == nil {
		return nil, errors.New("pairing persistence callbacks are required")
	}
	if _, err := relayURL(relay); err != nil {
		return nil, err
	}
	label = strings.TrimSpace(label)
	if !validDeviceLabel(label) {
		return nil, errors.New("invalid companion device label")
	}

	joinToken, err := random32()
	if err != nil {
		return nil, err
	}
	defer clear(joinToken)
	psk, err := random32()
	if err != nil {
		return nil, err
	}
	defer clear(psk)
	for string(joinToken) == string(psk) {
		if _, err := rand.Read(psk); err != nil {
			return nil, err
		}
	}
	linkID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	endpointID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	endpointSecret, err := random32()
	if err != nil {
		return nil, err
	}
	noiseKeys, err := noiseKeypair()
	if err != nil {
		return nil, err
	}
	encodedJoinToken := base64.RawURLEncoding.EncodeToString(joinToken)
	joinTokenHash, err := protocol.JoinTokenHash(encodedJoinToken)
	if err != nil {
		return nil, err
	}

	peer, err := dialRelay(setup, relay, protocol.PairingAuthorization)
	if err != nil {
		return nil, err
	}
	var created struct {
		PairID    string `json:"pairId"`
		SideID    string `json:"sideId"`
		ExpiresAt int64  `json:"expiresAt"`
	}
	if err := peer.request(setup, "pair.create", protocol.PairCreateBody{JoinTokenHash: joinTokenHash}, &created); err != nil {
		peer.close()
		return nil, err
	}
	invite := protocol.PairingInvite{
		Protocol: protocol.PairingInviteProtocolName, V: protocol.PairingInviteProtocolVersion,
		RelayURL: relay, PairID: created.PairID, CreatorSideID: created.SideID, LinkID: linkID,
		JoinToken: encodedJoinToken, PSK: base64.RawURLEncoding.EncodeToString(psk), ExpiresAt: created.ExpiresAt,
	}
	if err := protocol.ValidatePairingInviteAt(invite, time.Now().Unix()); err != nil {
		peer.close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	return &pairingAttempt{
		ctx: ctx, cancel: cancel, peer: peer, invite: invite, label: label, persist: persist, discard: discard,
		decision: make(chan bool, 1), done: make(chan struct{}),
		state:    PairingState{Phase: pairingShowingQR, PairID: invite.PairID, ExpiresAt: invite.ExpiresAt},
		endpoint: endpointID, secret: endpointSecret, noiseKeys: noiseKeys,
		nextIn: 1, pending: make(map[int64][]byte),
	}, nil
}

func companionDeviceLabel() string {
	label, err := os.Hostname()
	if err != nil || strings.TrimSpace(label) == "" {
		return "Remote DaVinci Companion"
	}
	runes := []rune(strings.TrimSpace(label))
	if len(runes) > 80 {
		runes = runes[:80]
	}
	label = string(runes)
	if !validDeviceLabel(label) {
		return "Remote DaVinci Companion"
	}
	return label
}

func (attempt *pairingAttempt) snapshot() PairingState {
	attempt.mu.RLock()
	defer attempt.mu.RUnlock()
	state := attempt.state
	state.RequestedPermissions = append([]string(nil), state.RequestedPermissions...)
	return state
}

func (attempt *pairingAttempt) setState(state PairingState) {
	attempt.mu.Lock()
	attempt.state = state
	attempt.mu.Unlock()
}

func (attempt *pairingAttempt) decide(approve bool, pairID string) error {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if pairID == "" || pairID != attempt.invite.PairID || attempt.state.Phase != pairingAwaitingApproval || attempt.decided {
		return errors.New("pairing is not awaiting approval")
	}
	attempt.decided = true
	attempt.decision <- approve
	return nil
}

func (attempt *pairingAttempt) stop(pairID string) error {
	attempt.mu.Lock()
	if pairID == "" || pairID != attempt.invite.PairID {
		attempt.mu.Unlock()
		return errors.New("pairing attempt did not match")
	}
	switch attempt.state.Phase {
	case pairingShowingQR, pairingHandshaking, pairingAwaitingApproval:
	default:
		attempt.mu.Unlock()
		return errors.New("pairing can no longer be cancelled")
	}
	attempt.state = PairingState{Phase: pairingCancelled, PairID: attempt.invite.PairID}
	attempt.mu.Unlock()
	attempt.cancel()
	return nil
}

func (attempt *pairingAttempt) beginCommit(state PairingState) bool {
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.state.Phase != pairingAwaitingApproval {
		return false
	}
	attempt.state = state
	return true
}

func (attempt *pairingAttempt) finished() bool {
	select {
	case <-attempt.done:
		return true
	default:
		return false
	}
}

func (attempt *pairingAttempt) run() (Config, bool, error) {
	defer attempt.peer.close()
	defer func() {
		if !attempt.activated {
			attempt.cancelPair()
		}
		clear(attempt.secret)
		clear(attempt.noiseKeys.Private)
		attempt.invite.JoinToken = ""
		attempt.invite.PSK = ""
	}()

	ctx, cancel := context.WithDeadline(attempt.ctx, time.Unix(attempt.invite.ExpiresAt, 0))
	defer cancel()
	reads := readRelay(ctx, attempt.peer.connection, attempt.peer.pending)
	attempt.peer.pending = nil
	attempt.peer.pendingBytes = 0

	peerSideID, err := attempt.waitReady(ctx, reads)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	attempt.setState(PairingState{
		Phase: pairingHandshaking, PairID: attempt.invite.PairID, ExpiresAt: attempt.invite.ExpiresAt,
	})
	prologue, err := protocol.PairingNoisePrologue(
		attempt.invite.RelayURL, attempt.invite.PairID, attempt.invite.CreatorSideID,
		peerSideID, attempt.invite.LinkID, attempt.invite.ExpiresAt,
	)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	psk, err := base64.RawURLEncoding.DecodeString(attempt.invite.PSK)
	if err != nil || len(psk) != 32 {
		err = errors.New("invalid pairing PSK")
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN, Prologue: prologue, PresharedKey: psk,
	})
	clear(psk)
	attempt.invite.JoinToken = ""
	attempt.invite.PSK = ""
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}

	packet, err := attempt.nextPairPacket(ctx, reads, 1)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	payload, _, _, err := handshake.ReadMessage(nil, packet)
	if err != nil || len(payload) != 0 {
		err = errors.New("controller pairing handshake failed")
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	reply, receiveCipher, sendCipher, err := handshake.WriteMessage(nil, nil)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	if err := attempt.sendPairPacket(ctx, 1, reply); err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}

	packet, err = attempt.nextPairPacket(ctx, reads, 2)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	plaintext, err := receiveCipher.Decrypt(nil, nil, packet)
	if err != nil {
		err = errors.New("controller pairing identity authentication failed")
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	controller, err := validateControllerPairingIdentity(plaintext, attempt.invite.LinkID, attempt.endpoint, attempt.noiseKeys.Private)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	permissionMask := requestedPermissionMask(controller.Body.Permissions)
	if permissionMask == 0 {
		err = errors.New("controller requested no supported permissions")
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	attempt.setState(PairingState{
		Phase: pairingAwaitingApproval, PairID: attempt.invite.PairID, ExpiresAt: attempt.invite.ExpiresAt,
		ControllerLabel: controller.Body.DeviceLabel, ControllerFingerprint: controller.Body.NoiseFingerprint,
		RequestedPermissions: append([]string(nil), controller.Body.Permissions...),
	})

	approved, err := attempt.waitDecision(ctx, reads)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	if !approved {
		attempt.setState(PairingState{Phase: pairingRejected, PairID: attempt.invite.PairID})
		return Config{}, false, errPairingRejected
	}
	if !attempt.beginCommit(PairingState{
		Phase: pairingCommitting, PairID: attempt.invite.PairID, ExpiresAt: attempt.invite.ExpiresAt,
		ControllerLabel: controller.Body.DeviceLabel, ControllerFingerprint: controller.Body.NoiseFingerprint,
		RequestedPermissions: append([]string(nil), controller.Body.Permissions...),
	}) {
		err = errPairingCancelled
		attempt.finishWithError(err)
		return Config{}, false, err
	}

	secretDigest := sha256.Sum256(attempt.secret)
	config := Config{
		V: 1, RelayURL: attempt.invite.RelayURL, LinkID: attempt.invite.LinkID, EndpointID: attempt.endpoint,
		Secret: base64.RawURLEncoding.EncodeToString(attempt.secret), NoisePrivateKey: base64.RawURLEncoding.EncodeToString(attempt.noiseKeys.Private),
		ControllerEndpointID: controller.Body.EndpointID, ControllerNoiseKey: controller.Body.NoiseKey,
		ControllerFingerprint: controller.Body.NoiseFingerprint, ControllerLabel: controller.Body.DeviceLabel,
		PermissionMask: permissionMask, ActivationPending: true,
	}
	companionKey := base64.RawURLEncoding.EncodeToString(attempt.noiseKeys.Public)
	fingerprint, err := protocol.NoiseKeyFingerprint(companionKey)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	identityID, err := randomUUID()
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	identity, err := json.Marshal(protocol.PairingIdentityEnvelope{
		Protocol: protocol.PairingProtocolName, V: protocol.PairingProtocolVersion, Type: "identity", ID: identityID,
		Body: protocol.PairingIdentityBody{
			LinkID: attempt.invite.LinkID, EndpointID: attempt.endpoint, Role: protocol.Companion,
			NoiseKey: companionKey, NoiseFingerprint: fingerprint, DeviceLabel: attempt.label,
			Permissions: grantedPermissions(permissionMask), Capabilities: append([]string(nil), supportedOperations...),
		},
	})
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	encrypted, err := sendCipher.Encrypt(nil, nil, identity)
	if err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	if err := attempt.sendPairPacket(ctx, 2, encrypted); err != nil {
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	if err := attempt.persist(config); err != nil {
		err = fmt.Errorf("%w: %v", errConfigPersistence, err)
		attempt.finishWithError(err)
		return Config{}, false, err
	}
	staged := true
	commit := protocol.PairCommitBody{
		PairID: attempt.invite.PairID, SideID: attempt.invite.CreatorSideID, LinkID: attempt.invite.LinkID,
		Self: protocol.EndpointCommit{
			EndpointID: attempt.endpoint, Role: protocol.Companion,
			CredentialHash: base64.RawURLEncoding.EncodeToString(secretDigest[:]),
		},
		Peer: protocol.RoutingEndpoint{EndpointID: controller.Body.EndpointID, Role: protocol.Controller},
	}
	if err := attempt.commit(ctx, reads, commit, controller.Body.EndpointID); err != nil {
		config, staged, err = attempt.resolveCommitFailure(config, err)
		attempt.finishWithError(err)
		return config, staged, err
	}
	attempt.activated = true
	config.ActivationPending = false
	if err := attempt.persist(config); err != nil {
		config.ActivationPending = true
		err = fmt.Errorf("%w after relay activation: %v", errConfigPersistence, err)
		attempt.finishWithError(err)
		return config, true, err
	}
	return config, true, nil
}

func (attempt *pairingAttempt) resolveCommitFailure(config Config, err error) (Config, bool, error) {
	if !errors.Is(err, errPairingCommitRejected) {
		return config, true, err
	}
	if discardErr := attempt.discard(); discardErr != nil {
		return config, true, errors.Join(err, fmt.Errorf("%w: %v", errConfigPersistence, discardErr))
	}
	return Config{}, false, err
}

func validateControllerPairingIdentity(data []byte, linkID, companionEndpointID string, companionPrivate []byte) (protocol.PairingIdentityEnvelope, error) {
	identity, err := protocol.ParsePairing(data)
	if err != nil || identity.Body.Role != protocol.Controller || identity.Body.LinkID != linkID || identity.Body.EndpointID == companionEndpointID ||
		!validDeviceLabel(identity.Body.DeviceLabel) {
		return protocol.PairingIdentityEnvelope{}, errors.New("invalid controller pairing identity")
	}
	capabilities := make(map[string]bool, len(identity.Body.Capabilities))
	for _, capability := range identity.Body.Capabilities {
		capabilities[capability] = true
	}
	for _, permission := range identity.Body.Permissions {
		if !capabilities[permission] {
			return protocol.PairingIdentityEnvelope{}, errors.New("invalid controller pairing identity")
		}
	}
	key, err := decode32(identity.Body.NoiseKey)
	if err != nil || !contributoryX25519PublicKey(key, companionPrivate) {
		return protocol.PairingIdentityEnvelope{}, errors.New("invalid controller pairing identity")
	}
	return identity, nil
}

func (attempt *pairingAttempt) waitReady(ctx context.Context, reads <-chan relayRead) (string, error) {
	for {
		envelope, err := nextPairingServerMessage(ctx, reads)
		if err != nil {
			return "", err
		}
		switch envelope.Type {
		case "pair.ready":
			var ready struct {
				PairID     string `json:"pairId"`
				PeerSideID string `json:"peerSideId"`
				ExpiresAt  int64  `json:"expiresAt"`
			}
			if envelope.DecodeBody(&ready) != nil || ready.PairID != attempt.invite.PairID ||
				!uuidPattern.MatchString(ready.PeerSideID) || ready.PeerSideID == attempt.invite.CreatorSideID ||
				ready.ExpiresAt != attempt.invite.ExpiresAt {
				return "", errors.New("relay returned an invalid pairing peer")
			}
			return ready.PeerSideID, nil
		case "pair.closed", "error":
			return "", errors.New("relay closed the pairing attempt")
		}
	}
}

func (attempt *pairingAttempt) nextPairPacket(ctx context.Context, reads <-chan relayRead, sequence int64) ([]byte, error) {
	if sequence != attempt.nextIn {
		return nil, errors.New("unexpected pairing frame sequence")
	}
	if packet, ok := attempt.pending[sequence]; ok {
		delete(attempt.pending, sequence)
		attempt.pendingBytes -= len(packet)
		attempt.nextIn++
		return packet, nil
	}
	for {
		envelope, err := nextPairingServerMessage(ctx, reads)
		if err != nil {
			return nil, err
		}
		switch envelope.Type {
		case "pair.frame":
			var frame protocol.PairFrameBody
			if envelope.DecodeBody(&frame) != nil || frame.PairID != attempt.invite.PairID || frame.Seq < sequence {
				return nil, errors.New("unexpected pairing frame")
			}
			if _, exists := attempt.pending[frame.Seq]; exists || frame.Seq-sequence > int64(protocol.MaxRelayReorderFrames) {
				return nil, errors.New("unexpected pairing frame")
			}
			if len(frame.Payload) > base64.RawURLEncoding.EncodedLen(protocol.MaxRelayPayloadBytes) {
				return nil, errors.New("invalid pairing frame payload")
			}
			packet, err := base64.RawURLEncoding.DecodeString(frame.Payload)
			if err != nil || len(packet) == 0 || len(packet) > protocol.MaxRelayPayloadBytes ||
				base64.RawURLEncoding.EncodeToString(packet) != frame.Payload {
				return nil, errors.New("invalid pairing frame payload")
			}
			if frame.Seq == sequence {
				attempt.nextIn++
				return packet, nil
			}
			if len(attempt.pending) >= protocol.MaxRelayReorderFrames || attempt.pendingBytes+len(packet) > protocol.MaxRelayReorderBytes {
				return nil, errors.New("pairing frame reorder buffer full")
			}
			attempt.pending[frame.Seq] = packet
			attempt.pendingBytes += len(packet)
		case "pair.closed", "error":
			return nil, errors.New("relay closed the pairing attempt")
		default:
			return nil, errors.New("unexpected relay message during pairing")
		}
	}
}

func (attempt *pairingAttempt) waitDecision(ctx context.Context, reads <-chan relayRead) (bool, error) {
	select {
	case approved := <-attempt.decision:
		if err := ctx.Err(); err != nil {
			return false, err
		}
		return approved, nil
	case received, ok := <-reads:
		if !ok || received.err != nil {
			return false, errors.New("relay disconnected during pairing approval")
		}
		return false, errors.New("unexpected relay message during pairing approval")
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

func nextPairingServerMessage(ctx context.Context, reads <-chan relayRead) (protocol.ServerEnvelope, error) {
	select {
	case received, ok := <-reads:
		if !ok || received.err != nil {
			if received.err != nil {
				return protocol.ServerEnvelope{}, received.err
			}
			return protocol.ServerEnvelope{}, errors.New("relay reader stopped")
		}
		envelope, err := protocol.ParseServer(received.raw)
		if err != nil {
			return protocol.ServerEnvelope{}, errors.New("relay returned an invalid pairing message")
		}
		return envelope, nil
	case <-ctx.Done():
		return protocol.ServerEnvelope{}, ctx.Err()
	}
}

func (attempt *pairingAttempt) sendPairPacket(ctx context.Context, sequence int64, packet []byte) error {
	if len(packet) == 0 || len(packet) > protocol.MaxRelayPayloadBytes {
		return errors.New("invalid pairing packet")
	}
	id, err := randomUUID()
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, attempt.peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: "pair.frame", ID: id,
		Body: protocol.PairFrameBody{
			PairID: attempt.invite.PairID, Seq: sequence,
			Payload: base64.RawURLEncoding.EncodeToString(packet),
		},
	})
}

func (attempt *pairingAttempt) commit(ctx context.Context, reads <-chan relayRead, body protocol.PairCommitBody, controllerEndpointID string) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	if err := wsjson.Write(ctx, attempt.peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: "pair.commit", ID: id, Body: body,
	}); err != nil {
		return err
	}
	for {
		envelope, err := nextPairingServerMessage(ctx, reads)
		if err != nil {
			return err
		}
		switch envelope.Type {
		case "pair.completed":
			var completed struct {
				PairID         string              `json:"pairId"`
				LinkID         string              `json:"linkId"`
				PeerEndpointID string              `json:"peerEndpointId"`
				PeerRole       protocol.DeviceRole `json:"peerRole"`
			}
			if envelope.DecodeBody(&completed) != nil || completed.PairID != attempt.invite.PairID ||
				completed.LinkID != attempt.invite.LinkID || completed.PeerEndpointID != controllerEndpointID ||
				completed.PeerRole != protocol.Controller {
				return errors.New("relay completed an unexpected pairing")
			}
			return nil
		case "ok":
			if envelope.ReplyTo != id {
				return errors.New("relay returned an unmatched pairing response")
			}
			var success struct {
				RequestType string `json:"requestType"`
				Result      struct {
					Pending bool   `json:"pending"`
					Active  bool   `json:"active"`
					LinkID  string `json:"linkId"`
				} `json:"result"`
			}
			if envelope.DecodeBody(&success) != nil || success.RequestType != "pair.commit" {
				return errors.New("relay returned an invalid pairing response")
			}
			if success.Result.Active {
				if success.Result.LinkID == attempt.invite.LinkID {
					return nil
				}
				return errors.New("relay activated an unexpected pairing")
			}
			if !success.Result.Pending {
				return errors.New("relay returned an invalid pairing response")
			}
		case "error":
			if envelope.ReplyTo == id {
				var failure struct {
					Code      protocol.ErrorCode `json:"code"`
					Retryable bool               `json:"retryable"`
				}
				if envelope.DecodeBody(&failure) != nil || failure.Code == "" {
					return errors.New("relay returned an invalid pairing error")
				}
				if !failure.Retryable {
					return fmt.Errorf("%w: %s", errPairingCommitRejected, failure.Code)
				}
				return fmt.Errorf("relay could not confirm the pairing commit: %s", failure.Code)
			}
			return errors.New("relay rejected a pairing message")
		case "pair.closed":
			return attempt.pairClosedCommitError(envelope)
		default:
			return errors.New("unexpected relay message while committing pairing")
		}
	}
}

func (attempt *pairingAttempt) pairClosedCommitError(envelope protocol.ServerEnvelope) error {
	var closed struct {
		PairID string `json:"pairId"`
		Reason string `json:"reason"`
	}
	if envelope.ReplyTo != "" || envelope.DecodeBody(&closed) != nil || closed.PairID != attempt.invite.PairID {
		return errors.New("relay closed an unexpected pairing")
	}
	switch closed.Reason {
	case "cancelled", "expired", "peer-disconnected", "failed":
		return fmt.Errorf("%w: pair closed (%s)", errPairingCommitRejected, closed.Reason)
	default:
		return errors.New("relay returned an invalid pairing closure")
	}
}

func (attempt *pairingAttempt) cancelPair() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	id, err := randomUUID()
	if err != nil {
		return
	}
	_ = wsjson.Write(ctx, attempt.peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: "pair.cancel", ID: id,
		Body: protocol.PairCancelBody{PairID: attempt.invite.PairID},
	})
}

func (attempt *pairingAttempt) finishWithError(err error) {
	phase := pairingFailed
	if errors.Is(err, context.DeadlineExceeded) || time.Now().Unix() >= attempt.invite.ExpiresAt {
		phase = pairingExpired
	} else if errors.Is(err, context.Canceled) || errors.Is(err, errPairingCancelled) {
		phase = pairingCancelled
	} else if errors.Is(err, errPairingRejected) {
		phase = pairingRejected
	}
	attempt.setState(PairingState{Phase: phase, PairID: attempt.invite.PairID})
}

func pairingStatus(phase string) string {
	switch phase {
	case pairingShowingQR:
		return "Waiting for iPhone or iPad to scan or paste pairing code"
	case pairingHandshaking:
		return "Controller found; securing pairing"
	case pairingAwaitingApproval:
		return "Controller is waiting for approval"
	case pairingCommitting:
		return "Finishing secure pairing"
	case pairingExpired:
		return "Pairing code expired"
	case pairingCancelled:
		return "Pairing cancelled"
	case pairingRejected:
		return "Pairing rejected"
	default:
		return "Pairing failed"
	}
}

func terminalPairingPhase(phase string) bool {
	switch phase {
	case pairingExpired, pairingCancelled, pairingRejected, pairingFailed:
		return true
	default:
		return false
	}
}
