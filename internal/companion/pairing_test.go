package companion

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	testPairingPairID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	testPairingCreatorID  = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	testPairingJoinerID   = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testPairingController = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
)

func TestQRPairingRequiresApprovalAndCompletesNNpsk0(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	controllerFirst := make(chan []byte, 1)
	controllerIdentity := make(chan []byte, 1)
	companionHandshake := make(chan []byte, 1)
	companionIdentity := make(chan []byte, 1)
	createdBody := make(chan protocol.PairCreateBody, 1)
	serverErrors := make(chan error, 1)
	releaseServer := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseServer) }) }
	var messageNumber atomic.Int64

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer connection.CloseNow()
		serve := func() error {
			if request.Header.Get("Authorization") != protocol.PairingAuthorization {
				return errors.New("pairing authorization was not used")
			}
			created, err := readPairingClient(ctx, connection, "pair.create")
			if err != nil {
				return err
			}
			var body protocol.PairCreateBody
			if created.DecodeBody(&body) != nil || body.JoinTokenHash == "" {
				return errors.New("pair.create did not include a join-token hash")
			}
			createdBody <- body
			expiresAt := time.Now().Unix() + protocol.PairingTTLSeconds
			if err := writePairingOK(ctx, connection, &messageNumber, created, map[string]any{
				"pairId": testPairingPairID, "sideId": testPairingCreatorID, "expiresAt": expiresAt,
			}); err != nil {
				return err
			}
			if err := writePairingServer(ctx, connection, &messageNumber, "pair.ready", "", map[string]any{
				"pairId": testPairingPairID, "peerSideId": testPairingJoinerID, "expiresAt": expiresAt,
			}); err != nil {
				return err
			}
			select {
			case packet := <-controllerFirst:
				if err := writePairingFrame(ctx, connection, &messageNumber, 1, packet); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
			frame, err := readPairingClient(ctx, connection, "pair.frame")
			if err != nil {
				return err
			}
			packet, err := pairingPacket(frame, 1)
			if err != nil {
				return err
			}
			companionHandshake <- packet
			select {
			case packet := <-controllerIdentity:
				if err := writePairingFrame(ctx, connection, &messageNumber, 2, packet); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
			}
			frame, err = readPairingClient(ctx, connection, "pair.frame")
			if err != nil {
				return err
			}
			packet, err = pairingPacket(frame, 2)
			if err != nil {
				return err
			}
			companionIdentity <- packet
			committed, err := readPairingClient(ctx, connection, "pair.commit")
			if err != nil {
				return err
			}
			var commit protocol.PairCommitBody
			if committed.DecodeBody(&commit) != nil || commit.PairID != testPairingPairID ||
				commit.SideID != testPairingCreatorID || commit.LinkID == "" ||
				commit.Self.Role != protocol.Companion || commit.Peer != (protocol.RoutingEndpoint{
				EndpointID: testPairingController, Role: protocol.Controller,
			}) {
				return errors.New("invalid companion pairing commit")
			}
			if err := writePairingOK(ctx, connection, &messageNumber, committed, map[string]any{"pending": true}); err != nil {
				return err
			}
			if err := writePairingServer(ctx, connection, &messageNumber, "pair.completed", "", map[string]any{
				"pairId": testPairingPairID, "linkId": commit.LinkID,
				"peerEndpointId": testPairingController, "peerRole": protocol.Controller,
			}); err != nil {
				return err
			}
			select {
			case <-releaseServer:
			case <-ctx.Done():
			}
			return nil
		}
		if err := serve(); err != nil {
			serverErrors <- err
		}
	}))
	defer server.Close()
	defer release()
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()
	relay := "wss" + strings.TrimPrefix(server.URL, "https")

	var savedMu sync.Mutex
	var saved []Config
	var discarded atomic.Int64
	attempt, err := newPairingAttempt(ctx, ctx, relay, "Test Mac", func(config Config) error {
		savedMu.Lock()
		saved = append(saved, config)
		savedMu.Unlock()
		return nil
	}, func() error {
		discarded.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.snapshot().Phase != pairingShowingQR {
		t.Fatalf("initial phase = %q", attempt.snapshot().Phase)
	}
	create := receivePairingValue(t, ctx, createdBody, "pair.create body")
	wantJoinHash, err := protocol.JoinTokenHash(attempt.invite.JoinToken)
	if err != nil || create.JoinTokenHash != wantJoinHash || attempt.invite.JoinToken == attempt.invite.PSK {
		t.Fatalf("join token binding was not independent: hash = %q, want %q, error = %v", create.JoinTokenHash, wantJoinHash, err)
	}

	psk, err := base64.RawURLEncoding.DecodeString(attempt.invite.PSK)
	if err != nil {
		t.Fatal(err)
	}
	prologue, err := protocol.PairingNoisePrologue(
		attempt.invite.RelayURL, attempt.invite.PairID, attempt.invite.CreatorSideID,
		testPairingJoinerID, attempt.invite.LinkID, attempt.invite.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	controllerHandshake, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNN, Initiator: true, Prologue: prologue, PresharedKey: psk,
	})
	if err != nil {
		t.Fatal(err)
	}
	message1, _, _, err := controllerHandshake.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	controllerFirst <- message1
	runResult := make(chan struct {
		config Config
		staged bool
		err    error
	}, 1)
	go func() {
		config, staged, err := attempt.run()
		runResult <- struct {
			config Config
			staged bool
			err    error
		}{config, staged, err}
	}()

	message2 := receivePairingValue(t, ctx, companionHandshake, "companion handshake")
	payload, controllerSend, controllerReceive, err := controllerHandshake.ReadMessage(nil, message2)
	if err != nil || len(payload) != 0 {
		t.Fatalf("NNpsk0 handshake failed: payload = %x, error = %v", payload, err)
	}
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic := base64.RawURLEncoding.EncodeToString(controllerKey.Public)
	controllerFingerprint, err := protocol.NoiseKeyFingerprint(controllerPublic)
	if err != nil {
		t.Fatal(err)
	}
	identityID, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	controllerPlaintext, err := json.Marshal(protocol.PairingIdentityEnvelope{
		Protocol: protocol.PairingProtocolName, V: protocol.PairingProtocolVersion, Type: "identity", ID: identityID,
		Body: protocol.PairingIdentityBody{
			LinkID: attempt.invite.LinkID, EndpointID: testPairingController, Role: protocol.Controller,
			NoiseKey: controllerPublic, NoiseFingerprint: controllerFingerprint, DeviceLabel: "Test iPhone",
			Permissions: []string{"resolve.page.edit", "future.action"}, Capabilities: []string{"resolve.page.edit", "future.action"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	encryptedControllerIdentity, err := controllerSend.Encrypt(nil, nil, controllerPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	controllerIdentity <- encryptedControllerIdentity
	waitForPairingPhase(t, attempt, pairingAwaitingApproval)

	savedMu.Lock()
	savesBeforeApproval := len(saved)
	savedMu.Unlock()
	if savesBeforeApproval != 0 {
		t.Fatal("credentials were persisted before local approval")
	}
	select {
	case <-companionIdentity:
		t.Fatal("companion identity/grant was sent before local approval")
	case <-time.After(50 * time.Millisecond):
	}
	if err := attempt.decide(true, attempt.invite.PairID); err != nil {
		t.Fatal(err)
	}
	if err := attempt.decide(false, attempt.invite.PairID); err == nil {
		t.Fatal("accepted a second pairing decision")
	}

	encryptedCompanionIdentity := receivePairingValue(t, ctx, companionIdentity, "companion identity")
	companionPlaintext, err := controllerReceive.Decrypt(nil, nil, encryptedCompanionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	companionIdentityEnvelope, err := protocol.ParsePairing(companionPlaintext)
	if err != nil {
		t.Fatal(err)
	}
	if companionIdentityEnvelope.Body.Role != protocol.Companion ||
		companionIdentityEnvelope.Body.LinkID != attempt.invite.LinkID ||
		!slices.Equal(companionIdentityEnvelope.Body.Permissions, []string{"resolve.page.edit"}) {
		t.Fatalf("unexpected companion grant: %#v", companionIdentityEnvelope.Body)
	}

	result := receivePairingValue(t, ctx, runResult, "pairing result")
	release()
	if result.err != nil || !result.staged || result.config.ActivationPending {
		t.Fatalf("pairing result = %#v, staged = %v, error = %v", result.config, result.staged, result.err)
	}
	if result.config.ControllerFingerprint != controllerFingerprint || result.config.PermissionMask != 1<<1 {
		t.Fatalf("stored trust metadata = %#v", result.config)
	}
	if err := result.config.validate(); err != nil {
		t.Fatalf("stored pairing config is invalid: %v", err)
	}
	savedMu.Lock()
	defer savedMu.Unlock()
	if len(saved) != 2 || !saved[0].ActivationPending || saved[1].ActivationPending || discarded.Load() != 0 {
		t.Fatalf("persistence sequence = %#v, discard count = %d", saved, discarded.Load())
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
}

func TestPairingFramesUseBoundedReordering(t *testing.T) {
	attempt := &pairingAttempt{
		invite: protocol.PairingInvite{PairID: testPairingPairID}, nextIn: 1,
		pending: make(map[int64][]byte),
	}
	first := bytes.Repeat([]byte{1}, 32)
	second := bytes.Repeat([]byte{2}, 64)
	reads := make(chan relayRead, 2)
	reads <- pairingRelayRead(t, 2, second)
	reads <- pairingRelayRead(t, 1, first)
	close(reads)

	got, err := attempt.nextPairPacket(t.Context(), reads, 1)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first reordered packet = %x, error = %v", got, err)
	}
	got, err = attempt.nextPairPacket(t.Context(), reads, 2)
	if err != nil || !bytes.Equal(got, second) || len(attempt.pending) != 0 || attempt.pendingBytes != 0 {
		t.Fatalf("second reordered packet = %x, pending = %d/%d, error = %v", got, len(attempt.pending), attempt.pendingBytes, err)
	}
}

func TestControllerPairingIdentityIsBoundToTheApprovedLink(t *testing.T) {
	companionKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(controllerKey.Public)
	fingerprint, err := protocol.NoiseKeyFingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := protocol.PairingIdentityEnvelope{
		Protocol: protocol.PairingProtocolName, V: protocol.PairingProtocolVersion, Type: "identity",
		ID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		Body: protocol.PairingIdentityBody{
			LinkID: testLinkID, EndpointID: testPairingController, Role: protocol.Controller,
			NoiseKey: publicKey, NoiseFingerprint: fingerprint, DeviceLabel: "Test iPhone",
			Permissions: []string{"resolve.page.edit"}, Capabilities: []string{"resolve.page.edit"},
		},
	}
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateControllerPairingIdentity(data, testLinkID, testCompanionID, companionKey.Private); err != nil {
		t.Fatalf("valid identity was rejected: %v", err)
	}
	identity.Body.LinkID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	data, err = json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateControllerPairingIdentity(data, testLinkID, testCompanionID, companionKey.Private); err == nil {
		t.Fatal("accepted an identity for a different link")
	}
}

func TestPairClosedCommitDiscardsOnlyAnExactValidatedAttempt(t *testing.T) {
	config := Config{V: 1, ActivationPending: true}
	var discards atomic.Int64
	attempt := &pairingAttempt{invite: protocol.PairingInvite{PairID: testPairingPairID}, discard: func() error {
		discards.Add(1)
		return nil
	}}
	exact := protocol.ServerEnvelope{Body: json.RawMessage(`{"pairId":"` + testPairingPairID + `","reason":"expired"}`)}
	got, staged, err := attempt.resolveCommitFailure(config, attempt.pairClosedCommitError(exact))
	if err == nil || staged || got.V != 0 || discards.Load() != 1 {
		t.Fatalf("exact closure: config = %#v, staged = %v, discards = %d, error = %v", got, staged, discards.Load(), err)
	}

	for name, envelope := range map[string]protocol.ServerEnvelope{
		"wrong pair":       {Body: json.RawMessage(`{"pairId":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee","reason":"expired"}`)},
		"unexpected reply": {ReplyTo: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", Body: exact.Body},
		"malformed":        {Body: json.RawMessage(`{"pairId":"` + testPairingPairID + `"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			classification := attempt.pairClosedCommitError(envelope)
			got, staged, err := attempt.resolveCommitFailure(config, classification)
			if errors.Is(err, errPairingCommitRejected) || !staged || got != config || discards.Load() != 1 {
				t.Fatalf("result: config = %#v, staged = %v, discards = %d, error = %v", got, staged, discards.Load(), err)
			}
		})
	}

	uncertain := errors.New("relay disconnected after commit")
	got, staged, err = attempt.resolveCommitFailure(config, uncertain)
	if !errors.Is(err, uncertain) || !staged || got != config || discards.Load() != 1 {
		t.Fatalf("transport result: config = %#v, staged = %v, discards = %d, error = %v", got, staged, discards.Load(), err)
	}
}

func TestPairingLoopbackAPIReportsStateAndAcceptsOneDecision(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	attempt := &pairingAttempt{
		ctx: ctx, cancel: cancel, invite: protocol.PairingInvite{PairID: testPairingPairID},
		decision: make(chan bool, 1), done: make(chan struct{}),
		state: PairingState{
			Phase: pairingAwaitingApproval, PairID: testPairingPairID, ControllerLabel: "Test iPhone",
			ControllerFingerprint: "sha256:test", RequestedPermissions: []string{"resolve.page.edit"},
		},
	}
	app := &App{relayURL: DefaultRelayURL, uiToken: "test-token", pairing: attempt, status: RelayStatus{Message: "Pairing"}}

	stateRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7314/api/state", nil)
	stateRequest.Header.Set(uiTokenHeader, app.uiToken)
	stateResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(stateResponse, stateRequest)
	if stateResponse.Code != http.StatusOK || strings.Contains(stateResponse.Body.String(), "joinToken") ||
		strings.Contains(stateResponse.Body.String(), "psk") || !strings.Contains(stateResponse.Body.String(), "awaitingApproval") {
		t.Fatalf("state status = %d, body = %s", stateResponse.Code, stateResponse.Body.String())
	}

	invalidStart := pairingAPIRequest(app, "/api/pairing/start", `{"extra":true}`)
	if invalidStart.Code != http.StatusBadRequest {
		t.Fatalf("invalid start status = %d, body = %s", invalidStart.Code, invalidStart.Body.String())
	}
	activeStart := pairingAPIRequest(app, "/api/pairing/start", `{}`)
	if activeStart.Code != http.StatusConflict {
		t.Fatalf("concurrent start status = %d, body = %s", activeStart.Code, activeStart.Body.String())
	}
	unauthorized := pairingAPIRequestWithToken(app, "/api/pairing/approve", `{"pairId":"`+testPairingPairID+`"}`, "")
	if unauthorized.Code != http.StatusForbidden {
		t.Fatalf("tokenless decision status = %d", unauthorized.Code)
	}
	invalid := pairingAPIRequest(app, "/api/pairing/approve", `{"pairId":"`+testPairingPairID+`","extra":true}`)
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("decision with extra field status = %d, body = %s", invalid.Code, invalid.Body.String())
	}
	stale := pairingAPIRequest(app, "/api/pairing/approve", `{"pairId":"eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}`)
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale-pair decision status = %d, body = %s", stale.Code, stale.Body.String())
	}
	approve := pairingAPIRequest(app, "/api/pairing/approve", `{"pairId":"`+testPairingPairID+`"}`)
	if approve.Code != http.StatusOK || !strings.Contains(approve.Body.String(), `"approved":true`) {
		t.Fatalf("approve status = %d, body = %s", approve.Code, approve.Body.String())
	}
	reject := pairingAPIRequest(app, "/api/pairing/reject", `{"pairId":"`+testPairingPairID+`"}`)
	if reject.Code != http.StatusConflict {
		t.Fatalf("second decision status = %d, body = %s", reject.Code, reject.Body.String())
	}

	cancel()
	ctx, cancel = context.WithCancel(t.Context())
	attempt = &pairingAttempt{
		ctx: ctx, cancel: cancel, invite: protocol.PairingInvite{PairID: testPairingPairID},
		decision: make(chan bool, 1), done: make(chan struct{}),
		state: PairingState{Phase: pairingAwaitingApproval, PairID: testPairingPairID},
	}
	app.pairing = attempt
	rejected := pairingAPIRequest(app, "/api/pairing/reject", `{"pairId":"`+testPairingPairID+`"}`)
	if rejected.Code != http.StatusOK || !strings.Contains(rejected.Body.String(), `"rejected":true`) {
		t.Fatalf("reject status = %d, body = %s", rejected.Code, rejected.Body.String())
	}
	select {
	case approved := <-attempt.decision:
		if approved {
			t.Fatal("reject API submitted approval")
		}
	default:
		t.Fatal("reject API did not submit a decision")
	}

	cancel()
	ctx, cancel = context.WithCancel(t.Context())
	attempt = &pairingAttempt{
		ctx: ctx, cancel: cancel, invite: protocol.PairingInvite{PairID: testPairingPairID},
		decision: make(chan bool, 1), done: make(chan struct{}),
		state: PairingState{Phase: pairingShowingQR, PairID: testPairingPairID},
	}
	app.pairing = attempt
	cancelResponse := pairingAPIRequest(app, "/api/pairing/cancel", `{"pairId":"`+testPairingPairID+`"}`)
	if cancelResponse.Code != http.StatusOK || attempt.snapshot().Phase != pairingCancelled {
		t.Fatalf("cancel status = %d, phase = %q", cancelResponse.Code, attempt.snapshot().Phase)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("cancel API did not cancel the active attempt")
	}

	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	attempt = &pairingAttempt{
		ctx: ctx, cancel: cancel, invite: protocol.PairingInvite{PairID: testPairingPairID},
		decision: make(chan bool, 1), done: make(chan struct{}),
		state: PairingState{Phase: pairingCommitting, PairID: testPairingPairID},
	}
	app.pairing = attempt
	cancelResponse = pairingAPIRequest(app, "/api/pairing/cancel", `{"pairId":"`+testPairingPairID+`"}`)
	if cancelResponse.Code != http.StatusConflict || attempt.snapshot().Phase != pairingCommitting {
		t.Fatalf("commit cancel status = %d, phase = %q", cancelResponse.Code, attempt.snapshot().Phase)
	}
	select {
	case <-ctx.Done():
		t.Fatal("cancel API interrupted an attempt that had started committing")
	default:
	}
}

func TestPairingCancelAndCommitTransitionAreAtomic(t *testing.T) {
	for range 100 {
		ctx, cancel := context.WithCancel(t.Context())
		attempt := &pairingAttempt{
			ctx: ctx, cancel: cancel, invite: protocol.PairingInvite{PairID: testPairingPairID},
			state: PairingState{Phase: pairingAwaitingApproval, PairID: testPairingPairID},
		}
		start := make(chan struct{})
		var stopped, committing bool
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			stopped = attempt.stop(testPairingPairID) == nil
		}()
		go func() {
			defer wait.Done()
			<-start
			committing = attempt.beginCommit(PairingState{Phase: pairingCommitting, PairID: testPairingPairID})
		}()
		close(start)
		wait.Wait()

		if stopped == committing {
			t.Fatalf("cancelled = %v, committing = %v", stopped, committing)
		}
		wantPhase := pairingCommitting
		if stopped {
			wantPhase = pairingCancelled
		}
		if phase := attempt.snapshot().Phase; phase != wantPhase {
			t.Fatalf("phase = %q, want %q", phase, wantPhase)
		}
		cancel()
	}
}

func TestGrantedPermissionsAreEnforcedInLiveSessions(t *testing.T) {
	called := false
	processor := newControlProcessor(func(context.Context, string) (map[string]any, error) {
		called = true
		return map[string]any{"ok": true}, nil
	}, []string{"resolve.page.edit"})
	if _, _, err := processor.handle(t.Context(), controlMessage(t, "hello", "10000000-0000-4000-8000-000000000001", protocol.ControlHelloBody{
		Role: protocol.Controller, Capabilities: []string{"resolve.page.edit"}, AppVersion: "test",
	})); err != nil {
		t.Fatal(err)
	}
	processor.now = func() time.Time { return time.UnixMilli(500) }
	response, send, err := processor.handle(t.Context(), controlMessage(t, "request", "10000000-0000-4000-8000-000000000002", map[string]any{
		"operation": "resolve.page.color", "args": map[string]any{}, "sentAt": 400, "expiresAt": 600,
	}))
	if err != nil || !send || called {
		t.Fatalf("forbidden operation: send = %v, called = %v, error = %v", send, called, err)
	}
	envelope, err := protocol.ParseControl(response)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if envelope.DecodeBody(&body) != nil || body.OK || body.Error.Code != "operation.forbidden" {
		t.Fatalf("forbidden response = %s", response)
	}
}

func readPairingClient(ctx context.Context, connection *websocket.Conn, want string) (protocol.ClientEnvelope, error) {
	var raw json.RawMessage
	if err := wsjson.Read(ctx, connection, &raw); err != nil {
		return protocol.ClientEnvelope{}, err
	}
	envelope, err := protocol.ParseClient(raw)
	if err != nil {
		return protocol.ClientEnvelope{}, err
	}
	if envelope.Type != want {
		return protocol.ClientEnvelope{}, fmt.Errorf("client message type = %q, want %q", envelope.Type, want)
	}
	return envelope, nil
}

func writePairingServer(ctx context.Context, connection *websocket.Conn, number *atomic.Int64, messageType, replyTo string, body any) error {
	return wsjson.Write(ctx, connection, struct {
		Protocol string `json:"protocol"`
		V        int64  `json:"v"`
		Type     string `json:"type"`
		ID       string `json:"id"`
		ReplyTo  string `json:"replyTo,omitempty"`
		Body     any    `json:"body"`
	}{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType,
		ID: fmt.Sprintf("90000000-0000-4000-8000-%012d", number.Add(1)), ReplyTo: replyTo, Body: body,
	})
}

func writePairingOK(ctx context.Context, connection *websocket.Conn, number *atomic.Int64, request protocol.ClientEnvelope, result map[string]any) error {
	return writePairingServer(ctx, connection, number, "ok", request.ID, map[string]any{
		"requestType": request.Type, "result": result,
	})
}

func writePairingFrame(ctx context.Context, connection *websocket.Conn, number *atomic.Int64, sequence int64, packet []byte) error {
	return writePairingServer(ctx, connection, number, "pair.frame", "", protocol.PairFrameBody{
		PairID: testPairingPairID, Seq: sequence, Payload: base64.RawURLEncoding.EncodeToString(packet),
	})
}

func pairingPacket(envelope protocol.ClientEnvelope, wantSequence int64) ([]byte, error) {
	var frame protocol.PairFrameBody
	if envelope.DecodeBody(&frame) != nil || frame.PairID != testPairingPairID || frame.Seq != wantSequence {
		return nil, errors.New("invalid pairing frame")
	}
	packet, err := base64.RawURLEncoding.DecodeString(frame.Payload)
	if err != nil {
		return nil, err
	}
	return packet, nil
}

func pairingRelayRead(t *testing.T, sequence int64, packet []byte) relayRead {
	t.Helper()
	raw, err := json.Marshal(struct {
		Protocol string                 `json:"protocol"`
		V        int64                  `json:"v"`
		Type     string                 `json:"type"`
		ID       string                 `json:"id"`
		Body     protocol.PairFrameBody `json:"body"`
	}{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: "pair.frame",
		ID:   fmt.Sprintf("90000000-0000-4000-8000-%012d", sequence),
		Body: protocol.PairFrameBody{PairID: testPairingPairID, Seq: sequence, Payload: base64.RawURLEncoding.EncodeToString(packet)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParseServer(raw); err != nil {
		t.Fatalf("invalid test relay message: %v", err)
	}
	return relayRead{raw: raw}
}

func waitForPairingPhase(t *testing.T, attempt *pairingAttempt, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if state := attempt.snapshot(); state.Phase == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pairing phase = %q, want %q", attempt.snapshot().Phase, want)
}

func pairingAPIRequest(app *App, path, body string) *httptest.ResponseRecorder {
	return pairingAPIRequestWithToken(app, path, body, app.uiToken)
}

func pairingAPIRequestWithToken(app *App, path, body, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7314"+path, strings.NewReader(body))
	request.Header.Set(uiTokenHeader, token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://127.0.0.1:7314")
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	return response
}

func receivePairingValue[T any](t *testing.T, ctx context.Context, values <-chan T, name string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-ctx.Done():
		var zero T
		t.Fatalf("timed out waiting for %s: %v", name, ctx.Err())
		return zero
	}
}
