package companion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	liveReorderWindow         = protocol.MaxRelayReorderFrames
	liveReorderBytes          = protocol.MaxRelayReorderBytes
	liveProductionOptIn       = "I_ACCEPT_PROVISIONING_MAY_LEAVE_PRODUCTION_IDENTITIES"
	liveDefaultLatencySamples = 20
	liveMaxLatencySamples     = 100
)

func TestLiveCanaryTargetGuard(t *testing.T) {
	for _, test := range []struct {
		name, relay, disposable, production string
		wantError                           bool
	}{
		{"disposable", "wss://dev.example/v1", "1", "", false},
		{"production explicit", DefaultRelayURL, "", liveProductionOptIn, false},
		{"production mislabeled disposable", DefaultRelayURL, "1", "", true},
		{"missing", "wss://dev.example/v1", "", "", true},
		{"both", "wss://dev.example/v1", "1", liveProductionOptIn, true},
		{"invalid disposable", "wss://dev.example/v1", "yes", "", true},
		{"invalid production", "wss://dev.example/v1", "", "yes", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := liveCanaryTargetError(test.relay, test.disposable, test.production); (got != nil) != test.wantError {
				t.Fatalf("liveCanaryTargetError() = %v, want error %v", got, test.wantError)
			}
		})
	}
}

func TestLiveFrameCollectorAllowsOnlyBoundedReordering(t *testing.T) {
	collector := liveFrameCollector{pending: make(map[int64]protocol.SessionFrameBody)}
	frame := func(sequence int64) protocol.SessionFrameBody {
		return protocol.SessionFrameBody{SessionID: testSessionID, Seq: sequence, Payload: base64.RawURLEncoding.EncodeToString([]byte{byte(sequence)})}
	}
	if ready, err := collector.add(1, frame(2)); err != nil || ready {
		t.Fatalf("buffer seq 2: ready = %v, error = %v", ready, err)
	}
	if ready, err := collector.add(1, frame(1)); err != nil || !ready {
		t.Fatalf("accept seq 1: ready = %v, error = %v", ready, err)
	}
	if buffered, found, err := collector.take(2); err != nil || !found || buffered.Seq != 2 {
		t.Fatal("buffered seq 2 was not delivered contiguously")
	}
	if _, err := collector.add(2, frame(1)); err == nil {
		t.Fatal("old frame was accepted")
	}
	if _, err := collector.add(2, frame(2+liveReorderWindow+1)); err == nil {
		t.Fatal("oversized sequence gap was accepted")
	}
}

func TestLiveLatencyPercentileUsesNearestRank(t *testing.T) {
	samples := make([]time.Duration, 20)
	for index := range samples {
		samples[index] = time.Duration(20-index) * time.Millisecond
	}
	for percentile, want := range map[int]time.Duration{50: 10 * time.Millisecond, 95: 19 * time.Millisecond, 99: 20 * time.Millisecond} {
		if got := liveLatencyPercentile(samples, percentile); got != want {
			t.Fatalf("p%d = %v, want %v", percentile, got, want)
		}
	}
	if samples[0] != 20*time.Millisecond || liveLatencyPercentile(nil, 50) != 0 {
		t.Fatal("percentile helper mutated input or accepted empty samples")
	}
}

func TestLiveLatencySampleCountValidation(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int
		ok    bool
	}{
		{"", liveDefaultLatencySamples, true},
		{"1", 1, true},
		{strconv.Itoa(liveMaxLatencySamples), liveMaxLatencySamples, true},
		{"0", 0, false},
		{strconv.Itoa(liveMaxLatencySamples + 1), 0, false},
		{"many", 0, false},
	} {
		got, err := liveLatencySampleCount(test.value)
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("sample count %q = %d, error = %v; want %d, valid = %v", test.value, got, err, test.want, test.ok)
		}
	}
	if liveCanaryTimeout(liveMaxLatencySamples) <= liveCanaryTimeout(liveDefaultLatencySamples) {
		t.Fatal("live canary timeout does not scale with latency sample count")
	}
}

func TestLiveRelayLifecycle(t *testing.T) {
	if os.Getenv("REMOTE_DAVINCI_E2E") != "1" {
		t.Skip("set REMOTE_DAVINCI_E2E=1 to run the destructive, self-cleaning live relay canary")
	}
	relay := os.Getenv("REMOTE_DAVINCI_RELAY_URL")
	if relay == "" {
		t.Fatal("REMOTE_DAVINCI_RELAY_URL is required")
	}
	if err := liveCanaryTargetError(
		relay,
		os.Getenv("REMOTE_DAVINCI_E2E_DISPOSABLE"),
		os.Getenv("REMOTE_DAVINCI_E2E_ALLOW_PRODUCTION"),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := relayURL(relay); err != nil {
		t.Fatal(err)
	}
	latencySampleCount, err := liveLatencySampleCount(os.Getenv("REMOTE_DAVINCI_E2E_LATENCY_SAMPLES"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), liveCanaryTimeout(latencySampleCount))
	defer cancel()
	controllerID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	controllerSecret, err := random32()
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	credentialHash := sha256.Sum256(controllerSecret)
	controllerAuth := bearerAuthorization(controllerID, base64.RawURLEncoding.EncodeToString(controllerSecret))
	companionAuth := ""
	var controller, companion *livePeer
	cleaned := false
	config, enrollment, err := Provision(ctx, relay, EnrollmentRequest{
		V:                        1,
		ControllerEndpointID:     controllerID,
		ControllerCredentialHash: base64.RawURLEncoding.EncodeToString(credentialHash[:]),
		ControllerNoiseKey:       base64.RawURLEncoding.EncodeToString(controllerKey.Public),
		DeviceLabel:              "Disposable live canary",
	})
	if config.V == 1 {
		companionAuth = bearerAuthorization(config.EndpointID, config.Secret)
		t.Cleanup(func() {
			if controller != nil {
				controller.close()
			}
			if companion != nil {
				companion.close()
			}
			if !cleaned {
				cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cleanupCancel()
				if cleanupErr := revokeLiveIdentities(cleanupContext, relay, config.LinkID, controllerAuth, companionAuth); cleanupErr != nil {
					t.Errorf("live canary cleanup: %v", cleanupErr)
				}
			}
		})
	}
	if err != nil {
		t.Fatal(err)
	}

	controller, err = dialLivePeer(ctx, relay, controllerAuth)
	if err != nil {
		t.Fatal(err)
	}
	var opened struct {
		SessionID string `json:"sessionId"`
	}
	err = controller.request(ctx, "session.open", protocol.LinkBody{LinkID: config.LinkID}, &opened)
	var relayFailure *liveRelayError
	if !errors.As(err, &relayFailure) || relayFailure.code != protocol.PeerOffline {
		t.Fatalf("controller-before-companion session.open error = %v, want %s", err, protocol.PeerOffline)
	}

	companion, err = dialLivePeer(ctx, relay, companionAuth)
	if err != nil {
		t.Fatal(err)
	}
	firstSession, err := openLiveSession(ctx, controller, companion, config.LinkID, controllerID, config.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	executions := 0
	var closedSessionRequest []byte
	latencies := make([]time.Duration, 0, latencySampleCount)
	if err := exerciseLiveNoiseSession(ctx, config, enrollment, controllerKey, controller, companion, firstSession, latencySampleCount, &latencies, &executions, &closedSessionRequest); err != nil {
		t.Fatal(err)
	}
	if executions != latencySampleCount || len(latencies) != latencySampleCount {
		t.Fatalf("no-op executions = %d, latency samples = %d, want %d each", executions, len(latencies), latencySampleCount)
	}
	t.Logf("live encrypted no-op control RTT: samples=%d method=nearest-rank p50_ms=%.3f p95_ms=%.3f p99_ms=%.3f",
		len(latencies),
		float64(liveLatencyPercentile(latencies, 50))/float64(time.Millisecond),
		float64(liveLatencyPercentile(latencies, 95))/float64(time.Millisecond),
		float64(liveLatencyPercentile(latencies, 99))/float64(time.Millisecond),
	)

	var closed struct {
		Closed bool `json:"closed"`
	}
	if err := controller.request(ctx, "session.close", protocol.SessionCloseBody{SessionID: firstSession}, &closed); err != nil || !closed.Closed {
		t.Fatalf("session.close failed: %v", err)
	}
	if err := requireClosedSession(ctx, controller, firstSession); err != nil {
		t.Fatal(err)
	}
	if err := requireClosedSession(ctx, companion, firstSession); err != nil {
		t.Fatal(err)
	}

	secondSession, err := openLiveSession(ctx, controller, companion, config.LinkID, controllerID, config.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	if secondSession == firstSession {
		t.Fatal("relay reused a closed session ID")
	}
	if err := exerciseLiveNoiseSession(ctx, config, enrollment, controllerKey, controller, companion, secondSession, 0, nil, &executions, nil); err != nil {
		t.Fatal(err)
	}
	beforeReplay := executions
	if err := requireClosedSessionFrameRejected(ctx, controller, firstSession, closedSessionRequest); err != nil {
		t.Fatal(err)
	}
	if executions != beforeReplay {
		t.Fatalf("closed-session replay executed: count changed from %d to %d", beforeReplay, executions)
	}
	if executions != latencySampleCount {
		t.Fatalf("closed-session request replayed; execution count = %d", executions)
	}

	controller.close()
	companion.close()
	controller, companion = nil, nil
	if err := revokeLiveIdentities(ctx, relay, config.LinkID, controllerAuth, companionAuth); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	if err := requireUnauthorized(ctx, relay, controllerAuth); err != nil {
		t.Fatal(err)
	}
	if err := requireUnauthorized(ctx, relay, companionAuth); err != nil {
		t.Fatal(err)
	}
}

type liveRelayError struct {
	operation string
	code      protocol.ErrorCode
}

func (failure *liveRelayError) Error() string {
	return fmt.Sprintf("relay rejected %s: %s", failure.operation, failure.code)
}

type liveUpgradeError struct {
	status int
}

func (failure *liveUpgradeError) Error() string {
	return fmt.Sprintf("relay WebSocket upgrade failed with status %d", failure.status)
}

type livePeer struct {
	connection *websocket.Conn
	events     []protocol.ServerEnvelope
	frames     map[string]*liveFrameCollector
}

func dialLivePeer(ctx context.Context, relay, authorization string) (*livePeer, error) {
	header := http.Header{}
	header.Set("Authorization", authorization)
	connection, response, err := websocket.Dial(ctx, relay, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if response != nil {
			return nil, &liveUpgradeError{status: response.StatusCode}
		}
		return nil, errors.New("relay WebSocket upgrade failed")
	}
	connection.SetReadLimit(maxFrameBytes)
	return &livePeer{connection: connection, frames: make(map[string]*liveFrameCollector)}, nil
}

func (peer *livePeer) close() {
	_ = peer.connection.Close(websocket.StatusNormalClosure, "live canary complete")
}

func (peer *livePeer) send(ctx context.Context, messageType string, body any) (string, error) {
	id, err := randomUUID()
	if err != nil {
		return "", err
	}
	err = wsjson.Write(ctx, peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType, ID: id, Body: body,
	})
	return id, err
}

func (peer *livePeer) request(ctx context.Context, messageType string, body, result any) error {
	id, err := peer.send(ctx, messageType, body)
	if err != nil {
		return err
	}
	for {
		envelope, err := peer.read(ctx)
		if err != nil {
			return err
		}
		if envelope.ReplyTo != id {
			peer.events = append(peer.events, envelope)
			continue
		}
		if envelope.Type == "error" {
			var body struct {
				Code protocol.ErrorCode `json:"code"`
			}
			if envelope.DecodeBody(&body) != nil || body.Code == "" {
				body.Code = protocol.Internal
			}
			return &liveRelayError{operation: messageType, code: body.Code}
		}
		var success struct {
			RequestType string          `json:"requestType"`
			Result      json.RawMessage `json:"result"`
		}
		if envelope.Type != "ok" || envelope.DecodeBody(&success) != nil || success.RequestType != messageType {
			return errors.New("relay returned an invalid correlated response")
		}
		if result == nil {
			return nil
		}
		if err := json.Unmarshal(success.Result, result); err != nil {
			return errors.New("relay returned an invalid result")
		}
		return nil
	}
}

func (peer *livePeer) read(ctx context.Context) (protocol.ServerEnvelope, error) {
	var raw json.RawMessage
	if err := wsjson.Read(ctx, peer.connection, &raw); err != nil {
		return protocol.ServerEnvelope{}, err
	}
	envelope, err := protocol.ParseServer(raw)
	if err != nil {
		return protocol.ServerEnvelope{}, errors.New("relay returned an invalid frame")
	}
	return envelope, nil
}

func (peer *livePeer) event(ctx context.Context, messageType string) (protocol.ServerEnvelope, error) {
	for {
		for index, envelope := range peer.events {
			if envelope.Type == messageType {
				peer.events = append(peer.events[:index], peer.events[index+1:]...)
				return envelope, nil
			}
			if envelope.Type == "error" {
				return protocol.ServerEnvelope{}, errors.New("relay returned an asynchronous error")
			}
		}
		envelope, err := peer.read(ctx)
		if err != nil {
			return protocol.ServerEnvelope{}, err
		}
		if envelope.Type == "error" {
			return protocol.ServerEnvelope{}, errors.New("relay returned an asynchronous error")
		}
		if envelope.Type == messageType {
			return envelope, nil
		}
		peer.events = append(peer.events, envelope)
	}
}

func openLiveSession(ctx context.Context, controller, companion *livePeer, linkID, controllerID, companionID string) (string, error) {
	var result struct {
		SessionID string `json:"sessionId"`
	}
	if err := controller.request(ctx, "session.open", protocol.LinkBody{LinkID: linkID}, &result); err != nil {
		return "", err
	}
	for _, expected := range []struct {
		peer   *livePeer
		peerID string
	}{{controller, companionID}, {companion, controllerID}} {
		envelope, err := expected.peer.event(ctx, "session.opened")
		if err != nil {
			return "", err
		}
		var opened struct {
			SessionID      string `json:"sessionId"`
			LinkID         string `json:"linkId"`
			PeerEndpointID string `json:"peerEndpointId"`
		}
		if envelope.DecodeBody(&opened) != nil || opened.SessionID != result.SessionID || opened.LinkID != linkID || opened.PeerEndpointID != expected.peerID {
			return "", errors.New("relay opened an inconsistent session")
		}
	}
	return result.SessionID, nil
}

func requireClosedSession(ctx context.Context, peer *livePeer, sessionID string) error {
	envelope, err := peer.event(ctx, "session.closed")
	if err != nil {
		return err
	}
	var closed struct {
		SessionID string `json:"sessionId"`
	}
	if envelope.DecodeBody(&closed) != nil || closed.SessionID != sessionID {
		return errors.New("relay closed an inconsistent session")
	}
	return nil
}

func exerciseLiveNoiseSession(
	ctx context.Context,
	config Config,
	enrollment EnrollmentResponse,
	controllerKey noise.DHKey,
	controller, companion *livePeer,
	sessionID string,
	requestSamples int,
	latencies *[]time.Duration,
	executions *int,
	capturedRequest *[]byte,
) error {
	host, err := newSecureChannel(config, sessionID)
	if err != nil {
		return err
	}
	host.processor.execute = func(_ context.Context, operation string) (map[string]any, error) {
		if operation != "resolve.page.edit" {
			return nil, &operationError{code: "operation.unsupported"}
		}
		*executions++
		return map[string]any{"page": "edit"}, nil
	}
	companionKey, err := decode32(enrollment.CompanionNoiseKey)
	if err != nil {
		return err
	}
	prologue, err := protocol.SessionNoisePrologue(config.LinkID, sessionID)
	if err != nil {
		return err
	}
	initiator, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeIK, Initiator: true, Prologue: prologue,
		StaticKeypair: controllerKey, PeerStatic: companionKey,
	})
	if err != nil {
		return err
	}
	messageOne, _, _, err := initiator.WriteMessage(nil, nil)
	if err != nil {
		return err
	}
	if err := sendLiveFrame(ctx, controller, sessionID, 1, messageOne); err != nil {
		return err
	}
	frame, err := receiveLiveFrame(ctx, companion, sessionID, 1)
	if err != nil {
		return err
	}
	packets, ready, err := host.receive(ctx, frame.Seq, frame.Payload)
	if err != nil || ready || len(packets) != 2 {
		return errors.New("companion failed the Noise IK response")
	}
	// Send and receive sequence 2 before sequence 1 exists, proving the bounded
	// collector handles actual relay reordering rather than relying on timing.
	if err := sendLiveFrame(ctx, companion, sessionID, 2, packets[1]); err != nil {
		return err
	}
	earlyEnvelope, err := controller.event(ctx, "session.frame")
	if err != nil {
		return err
	}
	var earlyFrame protocol.SessionFrameBody
	if earlyEnvelope.DecodeBody(&earlyFrame) != nil || earlyFrame.SessionID != sessionID || earlyFrame.Seq != 2 {
		return errors.New("relay did not deliver sequence 2 before sequence 1")
	}
	collector := &liveFrameCollector{pending: make(map[int64]protocol.SessionFrameBody)}
	controller.frames[sessionID] = collector
	if ready, err := collector.add(1, earlyFrame); err != nil || ready {
		return errors.New("controller failed to buffer sequence 2 before sequence 1")
	}
	if err := sendLiveFrame(ctx, companion, sessionID, 1, packets[0]); err != nil {
		return err
	}
	responseFrame, err := receiveLiveFrame(ctx, controller, sessionID, 1)
	if err != nil {
		return err
	}
	buffered, reordered := controller.frames[sessionID].pending[2]
	if !reordered || buffered.Seq != 2 {
		return errors.New("relay did not deliver sequence 2 before sequence 1")
	}
	responsePacket, err := decodeLivePacket(responseFrame.Payload)
	if err != nil {
		return err
	}
	_, controllerSend, controllerReceive, err := initiator.ReadMessage(nil, responsePacket)
	if err != nil {
		return errors.New("controller failed the Noise IK response")
	}
	hostHelloFrame, err := receiveLiveFrame(ctx, controller, sessionID, 2)
	if err != nil {
		return err
	}
	hostHelloPacket, err := decodeLivePacket(hostHelloFrame.Payload)
	if err != nil {
		return err
	}
	hostHello, err := controllerReceive.Decrypt(nil, nil, hostHelloPacket)
	if err != nil {
		return errors.New("controller failed to decrypt the companion hello")
	}
	if envelope, err := protocol.ParseControl(hostHello); err != nil || envelope.Type != "hello" {
		return errors.New("companion sent an invalid encrypted hello")
	}

	controllerHello, err := liveControlMessage("hello", protocol.ControlHelloBody{
		Role: protocol.Controller, Capabilities: []string{"resolve.page.edit"}, AppVersion: Version,
	})
	if err != nil {
		return err
	}
	encryptedHello, err := controllerSend.Encrypt(nil, nil, controllerHello)
	if err != nil {
		return err
	}
	if err := sendLiveFrame(ctx, controller, sessionID, 2, encryptedHello); err != nil {
		return err
	}
	frame, err = receiveLiveFrame(ctx, companion, sessionID, 2)
	if err != nil {
		return err
	}
	packets, ready, err = host.receive(ctx, frame.Seq, frame.Payload)
	if err != nil || !ready || len(packets) != 0 {
		return errors.New("companion rejected the controller hello")
	}
	if requestSamples == 0 {
		return nil
	}

	for sample := range requestSamples {
		sequence := int64(3 + sample)
		requestID, err := randomUUID()
		if err != nil {
			return err
		}
		now := time.Now().UnixMilli()
		request, err := liveControlMessageWithID("request", requestID, protocol.ControlRequestBody{
			Operation: "resolve.page.edit", Args: map[string]any{}, SentAt: now, ExpiresAt: now + 15_000,
		})
		if err != nil {
			return err
		}
		encryptedRequest, err := controllerSend.Encrypt(nil, nil, request)
		if err != nil {
			return err
		}
		if capturedRequest != nil && sample == 0 {
			*capturedRequest = append((*capturedRequest)[:0], encryptedRequest...)
		}
		started := time.Now()
		if err := sendLiveFrame(ctx, controller, sessionID, sequence, encryptedRequest); err != nil {
			return err
		}
		frame, err = receiveLiveFrame(ctx, companion, sessionID, sequence)
		if err != nil {
			return err
		}
		packets, ready, err = host.receive(ctx, frame.Seq, frame.Payload)
		if err != nil || !ready || len(packets) != 1 {
			return errors.New("companion rejected the encrypted canary request")
		}
		if err := sendLiveFrame(ctx, companion, sessionID, sequence, packets[0]); err != nil {
			return err
		}
		responseFrame, err = receiveLiveFrame(ctx, controller, sessionID, sequence)
		if err != nil {
			return err
		}
		responsePacket, err = decodeLivePacket(responseFrame.Payload)
		if err != nil {
			return err
		}
		plaintext, err := controllerReceive.Decrypt(nil, nil, responsePacket)
		if err != nil {
			return errors.New("controller failed to decrypt the canary response")
		}
		response, err := protocol.ParseControl(plaintext)
		if err != nil || response.Type != "response" || response.ReplyTo != requestID {
			return errors.New("companion sent an invalid canary response")
		}
		var body protocol.ControlSuccessBody
		if response.DecodeBody(&body) != nil || !body.OK {
			return errors.New("companion rejected the page canary")
		}
		result, ok := body.Result.(map[string]any)
		if !ok || result["page"] != "edit" {
			return errors.New("companion returned an invalid page result")
		}
		if latencies != nil {
			*latencies = append(*latencies, time.Since(started))
		}
	}
	eventSequence := int64(3 + requestSamples)
	eventPacket, err := host.pageChangedEvent(resolvePageObservation{page: "color", observedAt: time.Now()})
	if err != nil || eventPacket == nil {
		return errors.New("companion failed to create the page event")
	}
	if err := sendLiveFrame(ctx, companion, sessionID, eventSequence, eventPacket); err != nil {
		return err
	}
	eventFrame, err := receiveLiveFrame(ctx, controller, sessionID, eventSequence)
	if err != nil {
		return err
	}
	eventPacket, err = decodeLivePacket(eventFrame.Payload)
	if err != nil {
		return err
	}
	plaintext, err := controllerReceive.Decrypt(nil, nil, eventPacket)
	if err != nil {
		return errors.New("controller failed to decrypt the page event")
	}
	event, err := protocol.ParseControl(plaintext)
	if err != nil || event.Type != "event" {
		return errors.New("companion sent an invalid page event")
	}
	var eventBody protocol.ControlEventBody
	if event.DecodeBody(&eventBody) != nil || eventBody.Name != "resolve.page.changed" {
		return errors.New("companion sent an invalid page event")
	}
	eventData, ok := eventBody.Data.(map[string]any)
	if !ok || eventData["page"] != "color" {
		return errors.New("companion sent an invalid page event")
	}
	return nil
}

func requireClosedSessionFrameRejected(ctx context.Context, peer *livePeer, sessionID string, replay []byte) error {
	if len(replay) == 0 {
		return errors.New("live canary did not capture the closed-session request")
	}
	rejectionContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var result any
	err := peer.request(rejectionContext, "session.frame", protocol.SessionFrameBody{
		SessionID: sessionID, Seq: 3, Payload: base64.RawURLEncoding.EncodeToString(replay),
	}, &result)
	var rejection *liveRelayError
	if !errors.As(err, &rejection) || rejection.code != protocol.SessionNotFound {
		return fmt.Errorf("closed-session frame rejection = %v, want %s", err, protocol.SessionNotFound)
	}
	return nil
}

func sendLiveFrame(ctx context.Context, peer *livePeer, sessionID string, sequence int64, packet []byte) error {
	_, err := peer.send(ctx, "session.frame", protocol.SessionFrameBody{
		SessionID: sessionID, Seq: sequence, Payload: base64.RawURLEncoding.EncodeToString(packet),
	})
	return err
}

func receiveLiveFrame(ctx context.Context, peer *livePeer, sessionID string, sequence int64) (protocol.SessionFrameBody, error) {
	collector := peer.frames[sessionID]
	if collector == nil {
		collector = &liveFrameCollector{pending: make(map[int64]protocol.SessionFrameBody)}
		peer.frames[sessionID] = collector
	}
	if frame, found, err := collector.take(sequence); err != nil {
		return protocol.SessionFrameBody{}, err
	} else if found {
		return frame, nil
	}
	for {
		envelope, err := peer.event(ctx, "session.frame")
		if err != nil {
			return protocol.SessionFrameBody{}, err
		}
		var frame protocol.SessionFrameBody
		if envelope.DecodeBody(&frame) != nil {
			return protocol.SessionFrameBody{}, errors.New("relay forwarded an invalid session frame")
		}
		if frame.SessionID != sessionID {
			return protocol.SessionFrameBody{}, errors.New("relay forwarded a frame for an unexpected session")
		}
		ready, err := collector.add(sequence, frame)
		if err != nil {
			return protocol.SessionFrameBody{}, err
		}
		if ready {
			return frame, nil
		}
	}
}

type liveFrameCollector struct {
	pending map[int64]protocol.SessionFrameBody
	bytes   int
}

func (collector *liveFrameCollector) add(want int64, frame protocol.SessionFrameBody) (bool, error) {
	if frame.Seq < want {
		return false, errors.New("relay forwarded an old or duplicate session frame")
	}
	if frame.Seq == want {
		return true, nil
	}
	if frame.Seq-want > liveReorderWindow || len(collector.pending) >= liveReorderWindow {
		return false, errors.New("relay frame reorder window exceeded")
	}
	if _, duplicate := collector.pending[frame.Seq]; duplicate {
		return false, errors.New("relay forwarded a duplicate buffered session frame")
	}
	packet, err := decodeLivePacket(frame.Payload)
	if err != nil {
		return false, err
	}
	if collector.bytes+len(packet) > liveReorderBytes {
		return false, errors.New("relay frame reorder byte limit exceeded")
	}
	collector.pending[frame.Seq] = frame
	collector.bytes += len(packet)
	return false, nil
}

func (collector *liveFrameCollector) take(sequence int64) (protocol.SessionFrameBody, bool, error) {
	frame, found := collector.pending[sequence]
	if !found {
		return protocol.SessionFrameBody{}, false, nil
	}
	packet, err := decodeLivePacket(frame.Payload)
	if err != nil {
		return protocol.SessionFrameBody{}, false, err
	}
	delete(collector.pending, sequence)
	collector.bytes -= len(packet)
	return frame, true, nil
}

func decodeLivePacket(encoded string) ([]byte, error) {
	packet, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(packet) != encoded {
		return nil, errors.New("relay forwarded a non-canonical session payload")
	}
	return packet, nil
}

func liveControlMessage(messageType string, body any) ([]byte, error) {
	id, err := randomUUID()
	if err != nil {
		return nil, err
	}
	return liveControlMessageWithID(messageType, id, body)
}

func liveControlMessageWithID(messageType, id string, body any) ([]byte, error) {
	return json.Marshal(wireEnvelope{
		Protocol: protocol.ControlProtocolName, V: protocol.ControlProtocolVersion, Type: messageType, ID: id, Body: body,
	})
}

func bearerAuthorization(endpointID, secret string) string {
	return "Bearer rd1." + endpointID + "." + secret
}

func liveCanaryTargetError(relay, disposable, production string) error {
	if disposable != "" && disposable != "1" {
		return errors.New("REMOTE_DAVINCI_E2E_DISPOSABLE must be exactly 1")
	}
	if production != "" && production != liveProductionOptIn {
		return fmt.Errorf("REMOTE_DAVINCI_E2E_ALLOW_PRODUCTION must be exactly %s", liveProductionOptIn)
	}
	if (disposable == "1") == (production == liveProductionOptIn) {
		return fmt.Errorf("set REMOTE_DAVINCI_E2E_DISPOSABLE=1 only for a confirmed disposable stack, or set REMOTE_DAVINCI_E2E_ALLOW_PRODUCTION=%s for the dangerous production override", liveProductionOptIn)
	}
	if relay == DefaultRelayURL && production != liveProductionOptIn {
		return errors.New("the configured production relay requires the explicit production override")
	}
	return nil
}

func liveLatencySampleCount(value string) (int, error) {
	if value == "" {
		return liveDefaultLatencySamples, nil
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 1 || count > liveMaxLatencySamples {
		return 0, fmt.Errorf("REMOTE_DAVINCI_E2E_LATENCY_SAMPLES must be an integer from 1 to %d", liveMaxLatencySamples)
	}
	return count, nil
}

func liveCanaryTimeout(latencySamples int) time.Duration {
	return 2*time.Minute + time.Duration(latencySamples)*2*time.Second
}

func liveLatencyPercentile(samples []time.Duration, percentile int) time.Duration {
	if len(samples) == 0 || percentile < 1 || percentile > 100 {
		return 0
	}
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	rank := (percentile*len(ordered) + 99) / 100
	return ordered[rank-1]
}

func revokeLiveIdentities(ctx context.Context, relay, linkID, controllerAuth, companionAuth string) error {
	var failures []error
	for _, action := range []struct {
		name, authorization, messageType string
		body                             any
	}{
		{"link", controllerAuth, "link.revoke", protocol.LinkBody{LinkID: linkID}},
		{"controller endpoint", controllerAuth, "endpoint.revoke", map[string]any{}},
		{"companion endpoint", companionAuth, "endpoint.revoke", map[string]any{}},
	} {
		if err := revokeLiveIdentity(ctx, relay, action.authorization, action.messageType, action.body); err != nil {
			failures = append(failures, fmt.Errorf("%s cleanup: %w", action.name, err))
		}
	}
	return errors.Join(failures...)
}

func revokeLiveIdentity(ctx context.Context, relay, authorization, messageType string, body any) error {
	peer, err := dialLivePeer(ctx, relay, authorization)
	if err != nil {
		var upgrade *liveUpgradeError
		if errors.As(err, &upgrade) && upgrade.status == http.StatusUnauthorized {
			return nil
		}
		return err
	}
	defer peer.close()
	var result struct {
		Revoked bool `json:"revoked"`
	}
	if err := peer.request(ctx, messageType, body, &result); err != nil {
		return err
	}
	if !result.Revoked {
		return errors.New("relay did not acknowledge revocation")
	}
	return nil
}

func requireUnauthorized(ctx context.Context, relay, authorization string) error {
	header := http.Header{}
	header.Set("Authorization", authorization)
	connection, response, err := websocket.Dial(ctx, relay, &websocket.DialOptions{HTTPHeader: header})
	if connection != nil {
		connection.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		return errors.New("revoked bearer credential was not rejected with HTTP 401")
	}
	return nil
}
