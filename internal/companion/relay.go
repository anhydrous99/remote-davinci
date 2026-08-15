package companion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

type RelayStatus struct {
	Connected bool
	Secure    bool
	Message   string
}

var errEnrollmentTerminal = errors.New("enrollment is no longer authorized")

func RunRelay(ctx context.Context, config Config, update func(RelayStatus)) error {
	if err := config.validate(); err != nil {
		return err
	}
	delay := time.Second
	for ctx.Err() == nil {
		update(RelayStatus{Message: "Connecting to relay…"})
		connected := false
		err := runRelayConnection(ctx, config, func(status RelayStatus) {
			connected = connected || status.Connected
			update(status)
		})
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, errEnrollmentTerminal) {
			update(RelayStatus{Message: "Enrollment revoked or unauthorized; reset required"})
			return err
		}
		if connected {
			delay = time.Second
		}
		update(RelayStatus{Message: "Disconnected; retrying…"})
		if err := fullJitterSleep(ctx, delay); err != nil {
			return nil
		}
		if delay < 15*time.Minute {
			delay *= 2
			if delay > 15*time.Minute {
				delay = 15 * time.Minute
			}
		}
		_ = err // The GUI intentionally gets a sanitized status, never credentials or frames.
	}
	return nil
}

func fullJitterSleep(ctx context.Context, maximum time.Duration) error {
	value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum)+1))
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Duration(value.Int64()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func randomConnectionAge() time.Duration {
	value, err := rand.Int(rand.Reader, big.NewInt(21))
	if err != nil {
		return 100 * time.Minute
	}
	return time.Duration(90+value.Int64()) * time.Minute
}

func runRelayConnection(parent context.Context, config Config, update func(RelayStatus)) error {
	peer, err := dialRelay(parent, config.RelayURL, "Bearer rd1."+config.EndpointID+"."+config.Secret)
	if err != nil {
		var upgrade *relayUpgradeError
		if errors.As(err, &upgrade) && upgrade.status == http.StatusUnauthorized {
			return fmt.Errorf("%w: bearer credentials rejected", errEnrollmentTerminal)
		}
		return err
	}
	connection := peer.connection
	defer connection.CloseNow()

	var link struct {
		LinkID         string              `json:"linkId"`
		PeerEndpointID string              `json:"peerEndpointId"`
		PeerRole       protocol.DeviceRole `json:"peerRole"`
		Status         string              `json:"status"`
	}
	if err := peer.request(parent, "link.get", protocol.LinkBody{LinkID: config.LinkID}, &link); err != nil {
		var rejected *relayResponseError
		if errors.As(err, &rejected) && (rejected.code == protocol.Forbidden || rejected.code == protocol.Unauthenticated) {
			return fmt.Errorf("%w: configured link rejected", errEnrollmentTerminal)
		}
		return err
	}
	if link.LinkID != config.LinkID || link.PeerEndpointID != config.ControllerEndpointID || link.PeerRole != protocol.Controller {
		return errors.New("relay returned an unexpected configured link")
	}
	if link.Status != "active" {
		return fmt.Errorf("%w: link status %s", errEnrollmentTerminal, link.Status)
	}

	ctx, cancel := context.WithCancel(parent)
	timer := time.AfterFunc(randomConnectionAge(), cancel)
	defer func() {
		timer.Stop()
		cancel()
	}()
	pingFailure := make(chan error, 1)
	go pingRelay(ctx, connection, pingFailure)

	update(RelayStatus{Connected: true, Message: "Relay connected; waiting for controller"})
	var secure *secureChannel
	for {
		select {
		case err := <-pingFailure:
			return err
		default:
		}
		var raw json.RawMessage
		if len(peer.pending) != 0 {
			raw, peer.pending = peer.pending[0], peer.pending[1:]
		} else {
			if err := wsjson.Read(ctx, connection, &raw); err != nil {
				return err
			}
		}
		envelope, err := protocol.ParseServer(raw)
		if err != nil {
			return err
		}
		switch envelope.Type {
		case "session.opened":
			var opened struct {
				SessionID      string `json:"sessionId"`
				LinkID         string `json:"linkId"`
				PeerEndpointID string `json:"peerEndpointId"`
			}
			if envelope.DecodeBody(&opened) != nil || opened.LinkID != config.LinkID || opened.PeerEndpointID != config.ControllerEndpointID {
				return errors.New("relay opened an unexpected session")
			}
			secure, err = newSecureChannel(config, opened.SessionID)
			if err != nil {
				return err
			}
			update(RelayStatus{Connected: true, Message: "Controller connected; securing session…"})
		case "session.frame":
			if secure == nil {
				return errors.New("received a frame outside a session")
			}
			var frame protocol.SessionFrameBody
			if envelope.DecodeBody(&frame) != nil || frame.SessionID != secure.sessionID {
				return errors.New("received a frame for an unexpected session")
			}
			packets, ready, err := secure.receive(ctx, frame.Seq, frame.Payload)
			if err != nil {
				return err
			}
			for _, packet := range packets {
				if err := secure.sendPacket(ctx, connection, packet); err != nil {
					return err
				}
			}
			if ready {
				update(RelayStatus{Connected: true, Secure: true, Message: "Secure controller session"})
			}
		case "session.closed":
			var closed struct {
				SessionID string `json:"sessionId"`
			}
			if envelope.DecodeBody(&closed) != nil {
				return errors.New("relay closed an invalid session")
			}
			if secure == nil || closed.SessionID != secure.sessionID {
				continue
			}
			secure = nil
			update(RelayStatus{Connected: true, Message: "Relay connected; waiting for controller"})
		case "link.revoked":
			return fmt.Errorf("%w: controller link was revoked", errEnrollmentTerminal)
		case "error":
			return errors.New("relay rejected a session message")
		}
	}
}

func pingRelay(ctx context.Context, connection *websocket.Conn, failure chan<- error) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pingContext, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := connection.Ping(pingContext)
			cancel()
			if err != nil {
				select {
				case failure <- err:
				default:
				}
				_ = connection.CloseNow()
				return
			}
		}
	}
}

type secureChannel struct {
	sessionID     string
	expectedIn    int64
	nextOut       int64
	peerKey       []byte
	handshake     *noise.HandshakeState
	sendCipher    *noise.CipherState
	receiveCipher *noise.CipherState
	processor     *controlProcessor
	pending       map[int64][]byte
	pendingBytes  int
}

func newSecureChannel(config Config, sessionID string) (*secureChannel, error) {
	privateKey, err := decode32(config.NoisePrivateKey)
	if err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	peerKey, err := decode32(config.ControllerNoiseKey)
	if err != nil {
		return nil, err
	}
	prologue, err := protocol.SessionNoisePrologue(config.LinkID, sessionID)
	if err != nil {
		return nil, err
	}
	handshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeIK, Prologue: prologue,
		StaticKeypair: noise.DHKey{Private: privateKey, Public: private.PublicKey().Bytes()},
	})
	if err != nil {
		return nil, err
	}
	return &secureChannel{
		sessionID: sessionID, expectedIn: 1, nextOut: 1, peerKey: peerKey,
		handshake: handshake, processor: newControlProcessor(ExecuteOperation), pending: make(map[int64][]byte),
	}, nil
}

func (channel *secureChannel) receive(ctx context.Context, sequence int64, encoded string) ([][]byte, bool, error) {
	if sequence < channel.expectedIn {
		return nil, false, errors.New("old session frame sequence")
	}
	if _, exists := channel.pending[sequence]; exists {
		return nil, false, errors.New("duplicate session frame sequence")
	}
	if sequence-channel.expectedIn > int64(protocol.MaxRelayReorderFrames) {
		return nil, false, errors.New("session frame exceeds reorder window")
	}
	if len(encoded) > base64.RawURLEncoding.EncodedLen(protocol.MaxRelayPayloadBytes) {
		return nil, false, errors.New("invalid session frame payload")
	}
	packet, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(packet) > protocol.MaxRelayPayloadBytes || base64.RawURLEncoding.EncodeToString(packet) != encoded {
		return nil, false, errors.New("invalid session frame payload")
	}
	if sequence > channel.expectedIn {
		if len(channel.pending) >= protocol.MaxRelayReorderFrames || channel.pendingBytes+len(packet) > protocol.MaxRelayReorderBytes {
			return nil, false, errors.New("session frame reorder buffer full")
		}
		channel.pending[sequence] = packet
		channel.pendingBytes += len(packet)
		return nil, channel.sendCipher != nil && channel.processor.peerHello, nil
	}

	var outgoing [][]byte
	ready := false
	for {
		packets, packetReady, err := channel.receivePacket(ctx, packet)
		if err != nil {
			return nil, false, err
		}
		outgoing = append(outgoing, packets...)
		ready = packetReady
		channel.expectedIn++
		next, exists := channel.pending[channel.expectedIn]
		if !exists {
			return outgoing, ready, nil
		}
		delete(channel.pending, channel.expectedIn)
		channel.pendingBytes -= len(next)
		packet = next
	}
}

func (channel *secureChannel) receivePacket(ctx context.Context, packet []byte) ([][]byte, bool, error) {
	if channel.sendCipher == nil {
		payload, _, _, err := channel.handshake.ReadMessage(nil, packet)
		if err != nil || len(payload) != 0 || !bytes.Equal(channel.handshake.PeerStatic(), channel.peerKey) {
			return nil, false, errors.New("controller Noise identity check failed")
		}
		response, incoming, outgoing, err := channel.handshake.WriteMessage(nil, nil)
		if err != nil {
			return nil, false, err
		}
		channel.receiveCipher, channel.sendCipher = incoming, outgoing
		hello, err := controlHello()
		if err != nil {
			return nil, false, err
		}
		encryptedHello, err := channel.sendCipher.Encrypt(nil, nil, hello)
		if err != nil {
			return nil, false, err
		}
		return [][]byte{response, encryptedHello}, false, nil
	}

	plaintext, err := channel.receiveCipher.Decrypt(nil, nil, packet)
	if err != nil {
		return nil, false, err
	}
	response, send, err := channel.processor.handle(ctx, plaintext)
	if err != nil {
		return nil, false, err
	}
	if !send {
		return nil, channel.processor.peerHello, nil
	}
	encrypted, err := channel.sendCipher.Encrypt(nil, nil, response)
	if err != nil {
		return nil, false, err
	}
	return [][]byte{encrypted}, channel.processor.peerHello, nil
}

func (channel *secureChannel) sendPacket(ctx context.Context, connection *websocket.Conn, packet []byte) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	message := wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: "session.frame", ID: id,
		Body: protocol.SessionFrameBody{
			SessionID: channel.sessionID, Seq: channel.nextOut,
			Payload: base64.RawURLEncoding.EncodeToString(packet),
		},
	}
	channel.nextOut++
	return wsjson.Write(ctx, connection, message)
}
