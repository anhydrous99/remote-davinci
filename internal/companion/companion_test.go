package companion

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	testLinkID       = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	testSessionID    = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	testControllerID = "11111111-1111-4111-8111-111111111111"
	testCompanionID  = "22222222-2222-4222-8222-222222222222"
)

func TestControlProcessorValidatesAndDeduplicates(t *testing.T) {
	executions := 0
	processor := newControlProcessor(func(_ context.Context, operation string) (map[string]any, error) {
		if operation != "resolve.page.edit" {
			return nil, &operationError{code: "operation.unsupported"}
		}
		executions++
		return map[string]any{"page": "edit"}, nil
	})
	processor.now = func() time.Time { return time.UnixMilli(1_000) }
	hello := controlMessage(t, "hello", "20000000-0000-4000-8000-000000000001", map[string]any{
		"role": "controller", "capabilities": []string{"resolve.page.edit"}, "appVersion": "0.1.0",
	})
	if response, send, err := processor.handle(context.Background(), hello); err != nil || send || response != nil {
		t.Fatalf("hello response = %s, send = %v, error = %v", response, send, err)
	}

	requestID := "20000000-0000-4000-8000-000000000002"
	request := controlMessage(t, "request", requestID, map[string]any{
		"operation": "resolve.page.edit", "args": map[string]any{}, "sentAt": 1_000, "expiresAt": 2_000,
	})
	first, send, err := processor.handle(context.Background(), request)
	if err != nil || !send || executions != 1 {
		t.Fatalf("first request send = %v, executions = %d, error = %v", send, executions, err)
	}
	duplicate, send, err := processor.handle(context.Background(), request)
	if err != nil || !send || executions != 1 || !bytes.Equal(first, duplicate) {
		t.Fatalf("duplicate send = %v, executions = %d, equal = %v, error = %v", send, executions, bytes.Equal(first, duplicate), err)
	}
	parsed, err := protocol.ParseControl(first)
	if err != nil || parsed.Type != "response" || parsed.ReplyTo != requestID {
		t.Fatalf("response = %#v, error = %v", parsed, err)
	}

	for _, test := range []struct {
		id        string
		operation string
		sentAt    int64
		expiresAt int64
	}{
		{"20000000-0000-4000-8000-000000000003", "resolve.page.edit", 500, 999},
		{"20000000-0000-4000-8000-000000000004", "future.operation", 1_000, 2_000},
	} {
		message := controlMessage(t, "request", test.id, map[string]any{
			"operation": test.operation, "args": map[string]any{}, "sentAt": test.sentAt, "expiresAt": test.expiresAt,
		})
		response, send, err := processor.handle(context.Background(), message)
		if err != nil || !send {
			t.Fatalf("%s send = %v, error = %v", test.operation, send, err)
		}
		parsed, err := protocol.ParseControl(response)
		if err != nil {
			t.Fatal(err)
		}
		var body protocol.ControlFailureBody
		if parsed.DecodeBody(&body) != nil || body.OK || body.Error.Code == "" {
			t.Fatalf("failure response = %s", response)
		}
	}
	if executions != 1 {
		t.Fatalf("executions = %d, want 1", executions)
	}
	for len(processor.cache) < 256 {
		id := fmt.Sprintf("20000000-0000-4000-8000-%012x", len(processor.cache)+10)
		invalid := controlMessage(t, "request", id, map[string]any{
			"operation": "resolve.page.edit", "args": map[string]any{}, "sentAt": 500, "expiresAt": 999,
		})
		if _, send, err := processor.handle(context.Background(), invalid); err != nil || !send {
			t.Fatalf("fill cache size %d: send = %v, error = %v", len(processor.cache), send, err)
		}
	}
	overLimit := controlMessage(t, "request", "20000000-0000-4000-8000-000000000999", map[string]any{
		"operation": "resolve.page.edit", "args": map[string]any{}, "sentAt": 500, "expiresAt": 999,
	})
	if _, _, err := processor.handle(context.Background(), overLimit); err == nil || len(processor.cache) != 256 {
		t.Fatalf("request limit error = %v, cache size = %d", err, len(processor.cache))
	}
}

func TestResolvePageOperationsRequireAuthoritativeReadback(t *testing.T) {
	pages := []string{"cut", "edit", "fusion", "color"}
	for _, page := range pages {
		t.Run(page, func(t *testing.T) {
			called := false
			result, err := executeOperation(t.Context(), "resolve.page."+page, func(_ context.Context, name string, args ...string) ([]byte, error) {
				called = true
				if name != "/usr/bin/python3" || len(args) != 3 || args[0] != "-c" || args[2] != page {
					t.Fatalf("command = %s %#v", name, args)
				}
				get := strings.Index(args[1], "current = resolve.GetCurrentPage()")
				guard := strings.Index(args[1], "if current != requested:")
				open := strings.Index(args[1], "resolve.OpenPage(requested)")
				readback := strings.LastIndex(args[1], "current = resolve.GetCurrentPage()")
				if get < 0 || guard <= get || open <= guard || readback <= open {
					t.Fatal("Resolve command does not short-circuit and read back the selected page")
				}
				return []byte(page + "\n"), nil
			})
			if err != nil || !called || result["page"] != page {
				t.Fatalf("result = %#v, called = %v, error = %v", result, called, err)
			}
		})
	}

	if _, err := executeOperation(t.Context(), "resolve.page.color", func(context.Context, string, ...string) ([]byte, error) {
		return []byte("edit\n"), nil
	}); err == nil || err.Error() != "resolve.unavailable" {
		t.Fatalf("mismatched readback error = %v", err)
	}
	called := false
	if _, err := executeOperation(t.Context(), "resolve.page.media", func(context.Context, string, ...string) ([]byte, error) {
		called = true
		return nil, nil
	}); err == nil || err.Error() != "operation.unsupported" || called {
		t.Fatalf("unsupported operation called = %v, error = %v", called, err)
	}
}

func TestResolvePageMonitorRestartsAndReaps(t *testing.T) {
	timestamp := strings.Index(resolvePageMonitorScript, "observed_at = time.time_ns()")
	read := strings.Index(resolvePageMonitorScript, "page = resolve.GetCurrentPage()")
	write := strings.Index(resolvePageMonitorScript, `print(f"{observed_at}`)
	if timestamp < 0 || read <= timestamp || write <= read || !strings.Contains(resolvePageMonitorScript, "time.sleep(0.5)") {
		t.Fatal("Resolve monitor must timestamp before each 500ms page sample")
	}
	ctx, cancel := context.WithCancel(t.Context())
	var runs atomic.Int64
	var samples atomic.Int64
	reaped := make(chan struct{})
	started := time.Now()
	parsed, err := parseResolvePageObservation(fmt.Sprintf("%d\tedit", started.UnixNano()))
	if err != nil || parsed.page != "edit" || !parsed.observedAt.Equal(time.Unix(0, started.UnixNano())) {
		t.Fatalf("parsed observation = %#v, error = %v", parsed, err)
	}
	emitPage := func(emit func(resolvePageObservation) error, page string) error {
		return emit(resolvePageObservation{page: page, observedAt: started.Add(time.Duration(samples.Add(1)) * time.Millisecond)})
	}
	pages := monitorResolvePages(ctx, func(ctx context.Context, emit func(resolvePageObservation) error) error {
		switch runs.Add(1) {
		case 1:
			for _, page := range []string{"-", "edit", "edit", "media", "edit"} {
				if err := emitPage(emit, page); err != nil {
					return err
				}
			}
			return errors.New("monitor failed")
		default:
			for _, page := range []string{"edit", "color"} {
				if err := emitPage(emit, page); err != nil {
					return err
				}
			}
			<-ctx.Done()
			close(reaped)
			return ctx.Err()
		}
	})

	for index, want := range []string{"-", "edit", "edit", "media", "edit", "edit", "color"} {
		select {
		case got := <-pages:
			if got.page != want {
				t.Fatalf("page %d = %q, want %q", index, got.page, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for page %d", index)
		}
	}
	cancel()
	for range pages {
	}
	select {
	case <-reaped:
	default:
		t.Fatal("monitor closed before its runner was reaped")
	}
	if runs.Load() != 2 {
		t.Fatalf("monitor runs = %d, want 2", runs.Load())
	}
}

func TestSecureChannelInteroperatesWithNoiseIKAndReordersFrames(t *testing.T) {
	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	controllerKey, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	companionKey, err := suite.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	config := Config{
		V: 1, RelayURL: DefaultRelayURL, LinkID: testLinkID, EndpointID: testCompanionID,
		Secret:               base64.RawURLEncoding.EncodeToString(secret),
		NoisePrivateKey:      base64.RawURLEncoding.EncodeToString(companionKey.Private),
		ControllerEndpointID: testControllerID,
		ControllerNoiseKey:   base64.RawURLEncoding.EncodeToString(controllerKey.Public), ControllerLabel: "Test iPad",
	}
	channel, err := newSecureChannel(config, testSessionID)
	if err != nil {
		t.Fatal(err)
	}
	channel.processor.execute = func(_ context.Context, operation string) (map[string]any, error) {
		return map[string]any{"operation": operation}, nil
	}
	prologue, _ := protocol.SessionNoisePrologue(testLinkID, testSessionID)
	initiator, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Pattern: noise.HandshakeIK, Initiator: true, Prologue: prologue,
		StaticKeypair: controllerKey, PeerStatic: companionKey.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	messageOne, _, _, err := initiator.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	packets, ready, err := channel.receive(context.Background(), 1, base64.RawURLEncoding.EncodeToString(messageOne))
	if err != nil || ready || len(packets) != 2 {
		t.Fatalf("handshake packets = %d, ready = %v, error = %v", len(packets), ready, err)
	}
	_, controllerSend, controllerReceive, err := initiator.ReadMessage(nil, packets[0])
	if err != nil {
		t.Fatal(err)
	}
	hostHello, err := controllerReceive.Decrypt(nil, nil, packets[1])
	if err != nil {
		t.Fatal(err)
	}
	parsedHello, err := protocol.ParseControl(hostHello)
	if err != nil || parsedHello.Type != "hello" {
		t.Fatalf("host hello = %s, error = %v", hostHello, err)
	}
	var helloBody protocol.ControlHelloBody
	if parsedHello.DecodeBody(&helloBody) != nil || !reflect.DeepEqual(helloBody.Capabilities,
		[]string{"resolve.page.cut", "resolve.page.edit", "resolve.page.fusion", "resolve.page.color", "host.volume.toggle-mute"}) {
		t.Fatalf("host capabilities = %v", helloBody.Capabilities)
	}

	controllerHello := controlMessage(t, "hello", "20000000-0000-4000-8000-000000000010", map[string]any{
		"role": "controller", "capabilities": []string{"resolve.page.edit"}, "appVersion": "0.1.0",
	})
	encryptedHello, err := controllerSend.Encrypt(nil, nil, controllerHello)
	if err != nil {
		t.Fatal(err)
	}
	packets, ready, err = channel.receive(context.Background(), 2, base64.RawURLEncoding.EncodeToString(encryptedHello))
	if err != nil || !ready || len(packets) != 0 {
		t.Fatalf("controller hello packets = %d, ready = %v, error = %v", len(packets), ready, err)
	}

	requestIDs := []string{
		"20000000-0000-4000-8000-000000000011",
		"20000000-0000-4000-8000-000000000012",
	}
	now := time.Now().UnixMilli()
	encryptedRequests := make([][]byte, len(requestIDs))
	for index, requestID := range requestIDs {
		request := controlMessage(t, "request", requestID, map[string]any{
			"operation": "resolve.page.edit", "args": map[string]any{}, "sentAt": now, "expiresAt": now + 5_000,
		})
		encryptedRequests[index], err = controllerSend.Encrypt(nil, nil, request)
		if err != nil {
			t.Fatal(err)
		}
	}
	encodedSecond := base64.RawURLEncoding.EncodeToString(encryptedRequests[1])
	packets, ready, err = channel.receive(context.Background(), 4, encodedSecond)
	if err != nil || !ready || len(packets) != 0 || len(channel.pending) != 1 {
		t.Fatalf("buffered packets = %d, ready = %v, pending = %d, error = %v", len(packets), ready, len(channel.pending), err)
	}
	if _, _, err := channel.receive(context.Background(), 4, encodedSecond); err == nil {
		t.Fatal("accepted a duplicate buffered sequence")
	}
	packets, ready, err = channel.receive(context.Background(), 3, base64.RawURLEncoding.EncodeToString(encryptedRequests[0]))
	if err != nil || !ready || len(packets) != 2 || len(channel.pending) != 0 || channel.pendingBytes != 0 {
		t.Fatalf("drained packets = %d, ready = %v, pending = %d/%d, error = %v", len(packets), ready, len(channel.pending), channel.pendingBytes, err)
	}
	for index, packet := range packets {
		response, err := controllerReceive.Decrypt(nil, nil, packet)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := protocol.ParseControl(response)
		if err != nil || parsed.Type != "response" || parsed.ReplyTo != requestIDs[index] {
			t.Fatalf("control response = %s, error = %v", response, err)
		}
	}
	commandCompleted := time.Now()
	channel.lastPageCommandAt = commandCompleted
	channel.lastResolvePage = "color"
	stalePacket, err := channel.pageChangedEvent(resolvePageObservation{page: "edit", observedAt: commandCompleted.Add(-time.Millisecond)})
	if err != nil || stalePacket != nil {
		t.Fatalf("stale page event packet = %x, error = %v", stalePacket, err)
	}
	duplicatePacket, err := channel.pageChangedEvent(resolvePageObservation{page: "color", observedAt: commandCompleted.Add(time.Millisecond)})
	if err != nil || duplicatePacket != nil {
		t.Fatalf("duplicate page event packet = %x, error = %v", duplicatePacket, err)
	}
	eventPacket, err := channel.pageChangedEvent(resolvePageObservation{page: "edit", observedAt: commandCompleted.Add(2 * time.Millisecond)})
	if err != nil {
		t.Fatal(err)
	}
	eventPlaintext, err := controllerReceive.Decrypt(nil, nil, eventPacket)
	if err != nil {
		t.Fatal(err)
	}
	event, err := protocol.ParseControl(eventPlaintext)
	if err != nil || event.Type != "event" {
		t.Fatalf("page event = %s, error = %v", eventPlaintext, err)
	}
	var eventBody protocol.ControlEventBody
	if event.DecodeBody(&eventBody) != nil || eventBody.Name != "resolve.page.changed" ||
		eventBody.Data.(map[string]any)["page"] != "edit" {
		t.Fatalf("page event body = %#v", eventBody)
	}
	if packet, err := channel.pageChangedEvent(resolvePageObservation{page: "edit", observedAt: commandCompleted.Add(3 * time.Millisecond)}); err != nil || packet != nil {
		t.Fatalf("repeated page event packet = %x, error = %v", packet, err)
	}
	if packet, err := channel.pageChangedEvent(resolvePageObservation{page: "media", observedAt: commandCompleted.Add(4 * time.Millisecond)}); err != nil || packet != nil {
		t.Fatalf("unsupported page event packet = %x, error = %v", packet, err)
	}
	returnedPacket, err := channel.pageChangedEvent(resolvePageObservation{page: "edit", observedAt: commandCompleted.Add(5 * time.Millisecond)})
	if err != nil || returnedPacket == nil {
		t.Fatalf("returning page event packet = %x, error = %v", returnedPacket, err)
	}
	returnedPlaintext, err := controllerReceive.Decrypt(nil, nil, returnedPacket)
	if err != nil {
		t.Fatal(err)
	}
	returnedEvent, err := protocol.ParseControl(returnedPlaintext)
	if err != nil || returnedEvent.Type != "event" {
		t.Fatalf("returning page event = %s, error = %v", returnedPlaintext, err)
	}
	if packet, err := channel.pageChangedEvent(resolvePageObservation{page: "edit"}); err == nil || packet != nil {
		t.Fatalf("untimestamped page event packet = %x, error = %v", packet, err)
	}
	if _, _, err := channel.receive(context.Background(), 3, base64.RawURLEncoding.EncodeToString(encryptedRequests[0])); err == nil {
		t.Fatal("accepted an old sequence")
	}
	tooFar := channel.expectedIn + int64(protocol.MaxRelayReorderFrames) + 1
	if _, _, err := channel.receive(context.Background(), tooFar, encodedSecond); err == nil {
		t.Fatal("accepted a sequence outside the reorder window")
	}
}

func TestRelayReconcilesWithoutDroppingQueuedRevocationEvents(t *testing.T) {
	config := validTestConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	var connections atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		connections.Add(1)
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			serverErr <- err
			return
		}
		defer connection.CloseNow()
		var raw json.RawMessage
		if err := wsjson.Read(ctx, connection, &raw); err != nil {
			serverErr <- err
			return
		}
		linkGet, err := protocol.ParseClient(raw)
		if err != nil || linkGet.Type != "link.get" {
			serverErr <- fmt.Errorf("reconciliation request = %s: %w", raw, err)
			return
		}
		write := func(messageType, id, replyTo string, body any) error {
			return wsjson.Write(ctx, connection, struct {
				Protocol string `json:"protocol"`
				V        int64  `json:"v"`
				Type     string `json:"type"`
				ID       string `json:"id"`
				ReplyTo  string `json:"replyTo,omitempty"`
				Body     any    `json:"body"`
			}{protocol.ProtocolName, protocol.ProtocolVersion, messageType, id, replyTo, body})
		}
		if err := write("session.opened", "90000000-0000-4000-8000-000000000001", "", map[string]any{
			"sessionId": testSessionID, "linkId": config.LinkID, "peerEndpointId": config.ControllerEndpointID,
		}); err != nil {
			serverErr <- err
			return
		}
		if err := write("ok", "90000000-0000-4000-8000-000000000002", linkGet.ID, map[string]any{
			"requestType": "link.get", "result": map[string]any{
				"linkId": config.LinkID, "peerEndpointId": config.ControllerEndpointID,
				"peerRole": protocol.Controller, "status": "active",
			},
		}); err != nil {
			serverErr <- err
			return
		}
		if err := write("link.revoked", "90000000-0000-4000-8000-000000000003", "", map[string]any{"linkId": config.LinkID}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}))
	defer server.Close()
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()
	config.RelayURL = "wss" + strings.TrimPrefix(server.URL, "https")

	var statuses []string
	err := RunRelay(ctx, config, func(status RelayStatus) { statuses = append(statuses, status.Message) })
	if !errors.Is(err, errEnrollmentTerminal) {
		t.Fatalf("RunRelay error = %v, want terminal enrollment error", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 1 {
		t.Fatalf("terminal revocation reconnected %d times", connections.Load())
	}
	joined := strings.Join(statuses, "|")
	if !strings.Contains(joined, "Controller connected; securing session") || !strings.Contains(joined, "reset required") {
		t.Fatalf("queued/terminal statuses were lost: %v", statuses)
	}
}

func TestRelayTreatsUnauthorizedUpgradeAsTerminal(t *testing.T) {
	config := validTestConfig(t)
	var attempts atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		http.Error(response, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()
	config.RelayURL = "wss" + strings.TrimPrefix(server.URL, "https")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := RunRelay(ctx, config, func(RelayStatus) {}); !errors.Is(err, errEnrollmentTerminal) {
		t.Fatalf("RunRelay error = %v, want terminal enrollment error", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("unauthorized enrollment attempted %d reconnects", attempts.Load())
	}
	config.ActivationPending = true
	checkpointed := false
	if err := RevokeEnrollment(ctx, config, func(config Config) error {
		checkpointed = config.LinkRevoked
		return nil
	}); err != nil || !checkpointed {
		t.Fatalf("uncertain activation cleanup error = %v, checkpointed = %v", err, checkpointed)
	}
}

func TestEnrollmentValidationRejectsNonCanonicalCredentials(t *testing.T) {
	secret := bytes.Repeat([]byte{1}, 32)
	hash := sha256.Sum256(secret)
	key, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := EnrollmentRequest{
		V: 1, ControllerEndpointID: testControllerID,
		ControllerCredentialHash: base64.RawURLEncoding.EncodeToString(hash[:]),
		ControllerNoiseKey:       base64.RawURLEncoding.EncodeToString(key.Public), DeviceLabel: "Test iPad",
	}
	data, _ := json.Marshal(request)
	if _, err := ParseEnrollmentRequest(data); err != nil {
		t.Fatal(err)
	}
	request.ControllerCredentialHash += "="
	data, _ = json.Marshal(request)
	if _, err := ParseEnrollmentRequest(data); err == nil {
		t.Fatal("accepted padded/non-canonical credential hash")
	}
	request.ControllerCredentialHash = base64.RawURLEncoding.EncodeToString(hash[:])
	for _, lowOrder := range [][]byte{make([]byte, 32), append([]byte{1}, make([]byte, 31)...)} {
		request.ControllerNoiseKey = base64.RawURLEncoding.EncodeToString(lowOrder)
		data, _ = json.Marshal(request)
		if _, err := ParseEnrollmentRequest(data); err == nil {
			t.Fatalf("accepted non-contributory enrollment key %x", lowOrder)
		}
		config := validTestConfig(t)
		config.ControllerNoiseKey = request.ControllerNoiseKey
		if err := config.validate(); err == nil {
			t.Fatalf("accepted non-contributory configured key %x", lowOrder)
		}
	}
}

func TestProvisionCompletesRelayPairing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	const (
		pairID    = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		sideA     = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
		sideB     = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
		locator   = "123456"
		expiresAt = int64(2_000_000_000)
	)
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerSecret := bytes.Repeat([]byte{7}, 32)
	controllerHash := sha256.Sum256(controllerSecret)
	request := EnrollmentRequest{
		V: 1, ControllerEndpointID: testControllerID,
		ControllerCredentialHash: base64.RawURLEncoding.EncodeToString(controllerHash[:]),
		ControllerNoiseKey:       base64.RawURLEncoding.EncodeToString(controllerKey.Public),
		DeviceLabel:              "Test iPad",
	}

	var connectionCount, messageCount atomic.Int64
	persisted := make(chan Config, 2)
	var companionCommit, controllerCommit protocol.PairCommitBody
	creatorCommit := make(chan protocol.PairCommitBody, 1)
	serverErrors := make(chan error, 2)
	done := make(chan struct{}, 2)
	nextMessageID := func() string {
		return fmt.Sprintf("90000000-0000-4000-8000-%012d", messageCount.Add(1))
	}
	readRequest := func(connection *websocket.Conn, want string) (protocol.ClientEnvelope, error) {
		var raw json.RawMessage
		if err := wsjson.Read(ctx, connection, &raw); err != nil {
			return protocol.ClientEnvelope{}, err
		}
		envelope, err := protocol.ParseClient(raw)
		if err != nil {
			return protocol.ClientEnvelope{}, err
		}
		if envelope.Type != want {
			return protocol.ClientEnvelope{}, fmt.Errorf("request type = %s, want %s", envelope.Type, want)
		}
		return envelope, nil
	}
	writeServer := func(connection *websocket.Conn, messageType, replyTo string, body any) error {
		return wsjson.Write(ctx, connection, struct {
			Protocol string `json:"protocol"`
			V        int64  `json:"v"`
			Type     string `json:"type"`
			ID       string `json:"id"`
			ReplyTo  string `json:"replyTo,omitempty"`
			Body     any    `json:"body"`
		}{protocol.ProtocolName, protocol.ProtocolVersion, messageType, nextMessageID(), replyTo, body})
	}
	writeOK := func(connection *websocket.Conn, request protocol.ClientEnvelope, result map[string]any) error {
		return writeServer(connection, "ok", request.ID, map[string]any{"requestType": request.Type, "result": result})
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, httpRequest *http.Request) {
		defer func() { done <- struct{}{} }()
		if httpRequest.Header.Get("Authorization") != protocol.PairingAuthorization {
			serverErrors <- errors.New("missing pairing authorization")
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(response, httpRequest, nil)
		if err != nil {
			serverErrors <- err
			return
		}
		defer connection.CloseNow()

		serve := func() error {
			switch connectionCount.Add(1) {
			case 1:
				created, err := readRequest(connection, "pair.create")
				if err != nil {
					return err
				}
				if err := writeOK(connection, created, map[string]any{
					"pairId": pairID, "sideId": sideA, "locator": locator, "expiresAt": expiresAt,
				}); err != nil {
					return err
				}
				if err := writeServer(connection, "pair.ready", "", map[string]any{
					"pairId": pairID, "peerSideId": sideB, "expiresAt": expiresAt,
				}); err != nil {
					return err
				}
				committed, err := readRequest(connection, "pair.commit")
				if err != nil {
					return err
				}
				if err := committed.DecodeBody(&companionCommit); err != nil {
					return err
				}
				if companionCommit.PairID != pairID || companionCommit.SideID != sideA ||
					companionCommit.Self.Role != protocol.Companion ||
					companionCommit.Peer != (protocol.RoutingEndpoint{EndpointID: testControllerID, Role: protocol.Controller}) {
					return errors.New("invalid companion commit")
				}
				creatorCommit <- companionCommit
				return writeOK(connection, committed, map[string]any{"pending": true})
			case 2:
				joined, err := readRequest(connection, "pair.join")
				if err != nil {
					return err
				}
				var join protocol.PairJoinBody
				if joined.DecodeBody(&join) != nil || join.Locator != locator {
					return errors.New("invalid pair join")
				}
				if err := writeServer(connection, "pair.ready", "", map[string]any{
					"pairId": pairID, "peerSideId": sideA, "expiresAt": expiresAt,
				}); err != nil {
					return err
				}
				if err := writeOK(connection, joined, map[string]any{
					"pairId": pairID, "sideId": sideB, "expiresAt": expiresAt,
				}); err != nil {
					return err
				}
				select {
				case config := <-persisted:
					if !config.ActivationPending {
						return errors.New("configuration was not checkpointed before final commit")
					}
				case <-ctx.Done():
					return ctx.Err()
				}
				committed, err := readRequest(connection, "pair.commit")
				if err != nil {
					return err
				}
				if err := committed.DecodeBody(&controllerCommit); err != nil {
					return err
				}
				first := <-creatorCommit
				if controllerCommit.PairID != pairID || controllerCommit.SideID != sideB ||
					controllerCommit.LinkID != first.LinkID ||
					controllerCommit.Self != (protocol.EndpointCommit{EndpointID: testControllerID, Role: protocol.Controller, CredentialHash: request.ControllerCredentialHash}) ||
					controllerCommit.Peer != (protocol.RoutingEndpoint{EndpointID: first.Self.EndpointID, Role: protocol.Companion}) {
					return errors.New("pair commits are not reciprocal")
				}
				if err := writeServer(connection, "pair.completed", "", map[string]any{
					"pairId": pairID, "linkId": first.LinkID,
					"peerEndpointId": first.Self.EndpointID, "peerRole": protocol.Companion,
				}); err != nil {
					return err
				}
				return writeOK(connection, committed, map[string]any{"linkId": first.LinkID, "active": true})
			default:
				return errors.New("unexpected relay connection")
			}
		}
		if err := serve(); err != nil {
			serverErrors <- err
		}
	}))
	defer server.Close()
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()
	relay := "wss" + strings.TrimPrefix(server.URL, "https")

	config, enrollment, err := Provision(ctx, relay, request, func(config Config) error {
		persisted <- config
		return nil
	})
	if err != nil {
		select {
		case serverErr := <-serverErrors:
			t.Fatalf("Provision: %v (relay: %v)", err, serverErr)
		default:
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case serverErr := <-serverErrors:
			t.Fatal(serverErr)
		case <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case serverErr := <-serverErrors:
		t.Fatal(serverErr)
	default:
	}

	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	if config.RelayURL != relay || config.LinkID != enrollment.LinkID || config.EndpointID != enrollment.CompanionEndpointID ||
		config.ControllerEndpointID != testControllerID || enrollment.ControllerEndpointID != testControllerID ||
		config.ControllerNoiseKey != request.ControllerNoiseKey || config.ControllerLabel != request.DeviceLabel {
		t.Fatalf("inconsistent provision result: config = %#v, enrollment = %#v", config, enrollment)
	}
	secret, _ := decode32(config.Secret)
	secretHash := sha256.Sum256(secret)
	if companionCommit.LinkID != config.LinkID || companionCommit.Self.EndpointID != config.EndpointID ||
		companionCommit.Self.CredentialHash != base64.RawURLEncoding.EncodeToString(secretHash[:]) {
		t.Fatalf("companion commit does not match config: %#v", companionCommit)
	}
	privateBytes, _ := decode32(config.NoisePrivateKey)
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.CompanionNoiseKey != base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()) {
		t.Fatal("enrollment Noise key does not match the stored private key")
	}
	select {
	case saved := <-persisted:
		if saved.ActivationPending {
			t.Fatal("final configuration retained the activation checkpoint")
		}
	default:
		t.Fatal("final configuration was not persisted")
	}
}

func TestGUIRejectsDNSRebinding(t *testing.T) {
	app := &App{}
	request := httptest.NewRequest(http.MethodPost, "http://attacker.example/api/action", strings.NewReader(`{"operation":"resolve.page.edit"}`))
	request.Host = "attacker.example"
	request.Header.Set("Origin", "http://attacker.example")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	app.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("DNS-rebinding request status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestGUIRequiresLaunchScopedTokenForAPIs(t *testing.T) {
	first, err := NewApp(t.Context(), filepath.Join(t.TempDir(), "first.json"), DefaultRelayURL)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewApp(t.Context(), filepath.Join(t.TempDir(), "second.json"), DefaultRelayURL)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	decoded, err := base64.RawURLEncoding.DecodeString(first.uiToken)
	if err != nil || len(decoded) != 32 || first.uiToken == second.uiToken {
		t.Fatalf("launch tokens are not independent 32-byte values")
	}
	if launchURL := first.LaunchURL("http://127.0.0.1:7314"); !strings.Contains(launchURL, "?token="+first.uiToken) {
		t.Fatalf("launch URL does not carry the UI token: %s", launchURL)
	}

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7314/api/state", nil)
	response := httptest.NewRecorder()
	first.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("tokenless API status = %d, want %d", response.Code, http.StatusForbidden)
	}
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7314/api/state", nil)
	request.Header.Set(uiTokenHeader, first.uiToken)
	response = httptest.NewRecorder()
	first.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized API status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRevokeEnrollmentCheckpointsBeforeBestEffortEndpointRevocation(t *testing.T) {
	config := validTestConfig(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	var checkpointed atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer rd1."+config.EndpointID+"."+config.Secret {
			done <- errors.New("unexpected bearer authorization")
			http.Error(response, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, err := websocket.Accept(response, request, nil)
		if err != nil {
			done <- err
			return
		}
		defer connection.CloseNow()
		write := func(messageType, replyTo string, body any) error {
			return wsjson.Write(ctx, connection, struct {
				Protocol string `json:"protocol"`
				V        int64  `json:"v"`
				Type     string `json:"type"`
				ID       string `json:"id"`
				ReplyTo  string `json:"replyTo,omitempty"`
				Body     any    `json:"body"`
			}{protocol.ProtocolName, protocol.ProtocolVersion, messageType, "90000000-0000-4000-8000-000000000001", replyTo, body})
		}
		read := func(want string) (protocol.ClientEnvelope, error) {
			var raw json.RawMessage
			if err := wsjson.Read(ctx, connection, &raw); err != nil {
				return protocol.ClientEnvelope{}, err
			}
			envelope, err := protocol.ParseClient(raw)
			if err != nil || envelope.Type != want {
				return protocol.ClientEnvelope{}, fmt.Errorf("request type = %s, want %s: %w", envelope.Type, want, err)
			}
			return envelope, nil
		}

		linkRequest, err := read("link.revoke")
		if err != nil {
			done <- err
			return
		}
		var link protocol.LinkBody
		if linkRequest.DecodeBody(&link) != nil || link.LinkID != config.LinkID {
			done <- errors.New("wrong link revoked")
			return
		}
		// An already-revoked notification may race the correlated idempotent reply.
		if err := write("link.revoked", "", map[string]any{"linkId": config.LinkID}); err != nil {
			done <- err
			return
		}
		if err := write("ok", linkRequest.ID, map[string]any{
			"requestType": "link.revoke", "result": map[string]any{"revoked": true},
		}); err != nil {
			done <- err
			return
		}

		endpointRequest, err := read("endpoint.revoke")
		if err != nil {
			done <- err
			return
		}
		if endpointRequest.ID == "" || !checkpointed.Load() {
			done <- errors.New("endpoint revocation started before the durable link checkpoint")
			return
		}
		// Closing before the endpoint ack models a successful revoke whose reply was lost.
		done <- nil
	}))
	defer server.Close()
	originalClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = originalClient }()
	config.RelayURL = "wss" + strings.TrimPrefix(server.URL, "https")

	if err := RevokeEnrollment(ctx, config, func(checkpoint Config) error {
		if !checkpoint.LinkRevoked {
			t.Fatal("link revocation checkpoint was not marked")
		}
		checkpointed.Store(true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestResetRetainsCredentialsUntilRevocationSucceeds(t *testing.T) {
	config := validTestConfig(t)
	path := filepath.Join(t.TempDir(), "companion.json")
	if err := SaveConfig(path, config); err != nil {
		t.Fatal(err)
	}
	parent, stopParent := context.WithCancel(context.Background())
	stopParent()
	cancelled, allowRevoke := false, false
	var app *App
	app = &App{
		ctx: parent, store: FileConfigStore{Path: path}, relayURL: config.RelayURL, uiToken: "test-token",
		config: &config, status: RelayStatus{Connected: true, Secure: true},
		cancel: func() { cancelled = true },
		revoke: func(_ context.Context, got Config, persist func(Config) error) error {
			if got.EndpointID != config.EndpointID {
				t.Error("reset used the wrong configuration")
			}
			if _, err := os.Stat(path); err != nil || !app.state().Configured || !cancelled {
				t.Error("active relay was not stopped before fresh revocation")
			}
			if !allowRevoke {
				return errors.New("relay unavailable")
			}
			got.LinkRevoked = true
			return persist(got)
		},
	}

	reset := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7314/api/reset", strings.NewReader(`{"confirmation":"`+config.LinkID+`"}`))
		request.Header.Set("Origin", "http://127.0.0.1:7314")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(uiTokenHeader, app.uiToken)
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		return response
	}

	if response := reset(); response.Code != http.StatusBadGateway {
		t.Fatalf("failed reset status = %d, want %d", response.Code, http.StatusBadGateway)
	}
	if _, err := os.Stat(path); err != nil || !app.state().Configured || !cancelled || app.cancel == nil {
		t.Fatal("failed reset removed local credentials")
	}
	allowRevoke = true
	if response := reset(); response.Code != http.StatusOK {
		t.Fatalf("successful reset status = %d, body = %s", response.Code, response.Body.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config file still exists: %v", err)
	}
	if app.state().Configured || !cancelled {
		t.Fatal("successful reset retained in-memory credentials or relay")
	}
}

func TestResetRequestSecurity(t *testing.T) {
	config := validTestConfig(t)
	called := false
	app := &App{config: &config, uiToken: "test-token", revoke: func(context.Context, Config, func(Config) error) error { called = true; return nil }}
	tests := []struct {
		name        string
		origin      string
		contentType string
		body        string
		token       string
		want        int
	}{
		{"missing token", "http://127.0.0.1:7314", "application/json", `{"confirmation":"` + testLinkID + `"}`, "", http.StatusForbidden},
		{"wrong confirmation", "http://127.0.0.1:7314", "application/json", `{"confirmation":"wrong"}`, "test-token", http.StatusBadRequest},
		{"cross origin", "http://attacker.example", "application/json", `{"confirmation":"` + testLinkID + `"}`, "test-token", http.StatusForbidden},
		{"wrong media type", "http://127.0.0.1:7314", "application/jsonp", `{"confirmation":"` + testLinkID + `"}`, "test-token", http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7314/api/reset", strings.NewReader(test.body))
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set(uiTokenHeader, test.token)
			response := httptest.NewRecorder()
			app.Handler().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
	if called {
		t.Fatal("unsafe reset reached revocation")
	}
}

func TestForgetLocalEnrollmentRequiresExactConfirmationAndSuccessfulDeletion(t *testing.T) {
	config := validTestConfig(t)
	temporary := t.TempDir()
	path := filepath.Join(temporary, "companion.json")
	if err := SaveConfig(path, config); err != nil {
		t.Fatal(err)
	}
	cancelled := false
	app := &App{
		store: FileConfigStore{Path: path}, config: &config, uiToken: "test-token",
		cancel: func() { cancelled = true }, status: RelayStatus{Connected: true},
	}
	forget := func(confirmation string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:7314/api/forget", strings.NewReader(`{"confirmation":"`+confirmation+`"}`))
		request.Header.Set("Origin", "http://127.0.0.1:7314")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(uiTokenHeader, app.uiToken)
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		return response
	}

	if response := forget("wrong"); response.Code != http.StatusBadRequest || cancelled || !app.state().Configured {
		t.Fatalf("wrong confirmation status = %d, cancelled = %v, configured = %v", response.Code, cancelled, app.state().Configured)
	}
	blocked := filepath.Join(temporary, "not-a-config-file")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(blocked, "keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	app.store = FileConfigStore{Path: blocked}
	if response := forget(config.LinkID); response.Code != http.StatusInternalServerError || !cancelled || !app.state().Configured {
		t.Fatalf("failed deletion status = %d, cancelled = %v, configured = %v", response.Code, cancelled, app.state().Configured)
	}
	app.store = FileConfigStore{Path: path}
	response := forget(config.LinkID)
	if response.Code != http.StatusOK || app.state().Configured || !strings.Contains(response.Body.String(), "may remain") {
		t.Fatalf("successful local forget status = %d, configured = %v, body = %s", response.Code, app.state().Configured, response.Body.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact config file still exists: %v", err)
	}
}

func TestMuteResultReportsUnsupportedOutput(t *testing.T) {
	if _, err := parseMuteResult([]byte("unsupported\n"), nil); err == nil || err.Error() != "host.mute-unsupported" {
		t.Fatalf("unsupported result error = %v", err)
	}
	result, err := parseMuteResult([]byte("true\n"), nil)
	if err != nil || result["muted"] != true {
		t.Fatalf("supported result = %#v, error = %v", result, err)
	}
}

func validTestConfig(t *testing.T) Config {
	t.Helper()
	companionKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		V: 1, RelayURL: DefaultRelayURL, LinkID: testLinkID, EndpointID: testCompanionID,
		Secret:               base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
		NoisePrivateKey:      base64.RawURLEncoding.EncodeToString(companionKey.Private),
		ControllerEndpointID: testControllerID,
		ControllerNoiseKey:   base64.RawURLEncoding.EncodeToString(controllerKey.Public),
		ControllerLabel:      "Test iPad",
	}
}

func controlMessage(t *testing.T, messageType, id string, body any) []byte {
	t.Helper()
	message, err := json.Marshal(wireEnvelope{
		Protocol: protocol.ControlProtocolName, V: protocol.ControlProtocolVersion,
		Type: messageType, ID: id, Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return message
}
