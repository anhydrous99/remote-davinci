package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/aws/aws-lambda-go/events"
)

var unexpected = errors.New("unexpected store call")

type fakeStore struct {
	getEndpoint    func(context.Context, string) (*Endpoint, error)
	connect        func(context.Context, Connection, string) (*CloseSessionResult, error)
	disconnect     func(context.Context, string, int64) (*DisconnectResult, error)
	connection     func(context.Context, string, int64) (Connection, error)
	rateLimit      func(context.Context, string, string, int64, int64) error
	createPair     func(context.Context, Pair) error
	pairByID       func(context.Context, string, int64) (Pair, error)
	joinPair       func(context.Context, string, PairSide, int64) (Pair, error)
	commitPair     func(context.Context, string, PairCommit, int64) (CommitPairResult, error)
	cancelPair     func(context.Context, string, string, int64) (*Pair, error)
	link           func(context.Context, string) (*Link, error)
	revokeLink     func(context.Context, string, string, int64) (RevokeLinkResult, error)
	rotateEndpoint func(context.Context, string, string, int64) error
	revokeEndpoint func(context.Context, string, int64) (RevokeEndpointResult, error)
	openSession    func(context.Context, string, string, string, string, int64) (Session, error)
	session        func(context.Context, string, int64) (Session, error)
	closeSession   func(context.Context, string, string, int64) (*CloseSessionResult, error)
}

func (f *fakeStore) GetEndpoint(ctx context.Context, id string) (*Endpoint, error) {
	if f.getEndpoint == nil {
		return nil, unexpected
	}
	return f.getEndpoint(ctx, id)
}

func (f *fakeStore) Connect(ctx context.Context, connection Connection, hash string) (*CloseSessionResult, error) {
	if f.connect == nil {
		return nil, unexpected
	}
	return f.connect(ctx, connection, hash)
}

func (f *fakeStore) Disconnect(ctx context.Context, id string, now int64) (*DisconnectResult, error) {
	if f.disconnect == nil {
		return nil, unexpected
	}
	return f.disconnect(ctx, id, now)
}

func (f *fakeStore) Connection(ctx context.Context, id string, now int64) (Connection, error) {
	if f.connection == nil {
		return Connection{}, unexpected
	}
	return f.connection(ctx, id, now)
}

func (f *fakeStore) RateLimit(ctx context.Context, source, action string, limit, now int64) error {
	if f.rateLimit == nil {
		return unexpected
	}
	return f.rateLimit(ctx, source, action, limit, now)
}

func (f *fakeStore) CreatePair(ctx context.Context, pair Pair) error {
	if f.createPair == nil {
		return unexpected
	}
	return f.createPair(ctx, pair)
}

func (f *fakeStore) PairByID(ctx context.Context, id string, now int64) (Pair, error) {
	if f.pairByID == nil {
		return Pair{}, unexpected
	}
	return f.pairByID(ctx, id, now)
}

func (f *fakeStore) JoinPair(ctx context.Context, locator string, side PairSide, now int64) (Pair, error) {
	if f.joinPair == nil {
		return Pair{}, unexpected
	}
	return f.joinPair(ctx, locator, side, now)
}

func (f *fakeStore) CommitPair(ctx context.Context, id string, commit PairCommit, now int64) (CommitPairResult, error) {
	if f.commitPair == nil {
		return CommitPairResult{}, unexpected
	}
	return f.commitPair(ctx, id, commit, now)
}

func (f *fakeStore) CancelPair(ctx context.Context, pairID, connectionID string, now int64) (*Pair, error) {
	if f.cancelPair == nil {
		return nil, unexpected
	}
	return f.cancelPair(ctx, pairID, connectionID, now)
}

func (f *fakeStore) Link(ctx context.Context, id string) (*Link, error) {
	if f.link == nil {
		return nil, unexpected
	}
	return f.link(ctx, id)
}

func (f *fakeStore) RevokeLink(ctx context.Context, linkID, endpointID string, now int64) (RevokeLinkResult, error) {
	if f.revokeLink == nil {
		return RevokeLinkResult{}, unexpected
	}
	return f.revokeLink(ctx, linkID, endpointID, now)
}

func (f *fakeStore) RotateEndpoint(ctx context.Context, endpointID, hash string, now int64) error {
	if f.rotateEndpoint == nil {
		return unexpected
	}
	return f.rotateEndpoint(ctx, endpointID, hash, now)
}

func (f *fakeStore) RevokeEndpoint(ctx context.Context, endpointID string, now int64) (RevokeEndpointResult, error) {
	if f.revokeEndpoint == nil {
		return RevokeEndpointResult{}, unexpected
	}
	return f.revokeEndpoint(ctx, endpointID, now)
}

func (f *fakeStore) OpenSession(ctx context.Context, linkID, endpointID, connectionID, sessionID string, now int64) (Session, error) {
	if f.openSession == nil {
		return Session{}, unexpected
	}
	return f.openSession(ctx, linkID, endpointID, connectionID, sessionID, now)
}

func (f *fakeStore) Session(ctx context.Context, id string, now int64) (Session, error) {
	if f.session == nil {
		return Session{}, unexpected
	}
	return f.session(ctx, id, now)
}

func (f *fakeStore) CloseSession(ctx context.Context, sessionID, endpointID string, now int64) (*CloseSessionResult, error) {
	if f.closeSession == nil {
		return nil, unexpected
	}
	return f.closeSession(ctx, sessionID, endpointID, now)
}

type apiError string

func (e apiError) Error() string     { return string(e) }
func (e apiError) ErrorCode() string { return string(e) }

func uuid(tail int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", tail) }

func envelope(messageType string, body any) string {
	value, _ := json.Marshal(map[string]any{
		"protocol": protocol.ProtocolName, "v": protocol.ProtocolVersion,
		"type": messageType, "id": uuid(1), "body": body,
	})
	return string(value)
}

func socketEvent(connectionID, route, body string) WebSocketEvent {
	return WebSocketEvent{
		Headers: map[string]string{"Authorization": protocol.PairingAuthorization},
		Body:    body,
		RequestContext: events.APIGatewayWebsocketProxyRequestContext{
			RouteKey: route, ConnectionID: connectionID, DomainName: "example.invalid", Stage: "v1",
			Identity: events.APIGatewayRequestIdentity{SourceIP: "203.0.113.42"},
		},
	}
}

func testHandler(store Store, post Post) *Handler {
	return testHandlerWithLogger(store, post, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

func testHandlerWithLogger(store Store, post Post, logger *slog.Logger) *Handler {
	value := 10
	return NewHandler(HandlerDependencies{
		Store: store, Post: post, Now: func() int64 { return 100 },
		ID: func() string {
			result := uuid(value)
			value++
			return result
		},
		Logger: logger,
	})
}

func decodedMessageBody(t *testing.T, message Message) map[string]any {
	t.Helper()
	data, err := json.Marshal(message.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func parseResponse(t *testing.T, response WebSocketResponse) protocol.ServerEnvelope {
	t.Helper()
	message, err := protocol.ParseServer(response.Body)
	if err != nil {
		t.Fatalf("response body = %q: %v", response.Body, err)
	}
	return message
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestConnectAuthenticatesBearerAndStoresOnlySourceHash(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytesOf(32, 7))
	digest := sha256.Sum256(bytesOf(32, 7))
	credentialHash := base64.RawURLEncoding.EncodeToString(digest[:])
	endpointID := uuid(9)
	var saved Connection
	connectCalls := 0
	store := &fakeStore{
		getEndpoint: func(_ context.Context, id string) (*Endpoint, error) {
			return &Endpoint{EndpointID: id, CredentialHash: credentialHash, Role: protocol.Controller}, nil
		},
		connect: func(_ context.Context, connection Connection, hash string) (*CloseSessionResult, error) {
			connectCalls++
			saved = connection
			if hash != credentialHash {
				t.Fatalf("credential hash = %q", hash)
			}
			return nil, nil
		},
	}
	handler := testHandler(store, func(context.Context, string, Message, WebSocketEvent) error { return nil })
	event := socketEvent("one", "$connect", "")
	event.Headers["Authorization"] = "Bearer rd1." + endpointID + "." + secret
	response, err := handler.Handle(context.Background(), event)
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response = %#v, %v", response, err)
	}
	if saved.AuthMode != "endpoint" || saved.EndpointID != endpointID || saved.SourceKey != SourceKey("203.0.113.42") {
		t.Fatalf("saved = %#v", saved)
	}
	encoded, _ := json.Marshal(saved)
	if strings.Contains(string(encoded), "203.0.113.42") || strings.Contains(string(encoded), secret) {
		t.Fatalf("sensitive connection data stored: %s", encoded)
	}

	event.Headers["Authorization"] = "Bearer rd1." + endpointID + "." + base64.RawURLEncoding.EncodeToString(bytesOf(32, 8))
	response, err = handler.Handle(context.Background(), event)
	if err != nil || response.StatusCode != 401 || connectCalls != 1 {
		t.Fatalf("bad credential response = %#v, calls = %d, error = %v", response, connectCalls, err)
	}
}

func TestConnectReplacementNotifiesOnlyOldPeer(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytesOf(32, 4))
	digest := sha256.Sum256(bytesOf(32, 4))
	hash := base64.RawURLEncoding.EncodeToString(digest[:])
	controllerID, companionID := uuid(2), uuid(3)
	closed := &CloseSessionResult{ClosedNow: true, Session: Session{
		SessionID: uuid(4), LinkID: uuid(5), ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "old-controller", CompanionConnectionID: "companion", Status: "CLOSED",
	}}
	var targets []string
	handler := testHandler(&fakeStore{
		getEndpoint: func(context.Context, string) (*Endpoint, error) {
			return &Endpoint{EndpointID: controllerID, CredentialHash: hash}, nil
		},
		connect: func(context.Context, Connection, string) (*CloseSessionResult, error) { return closed, nil },
	}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		targets = append(targets, target+":"+message.Type)
		return nil
	})
	event := socketEvent("new-controller", "$connect", "")
	event.Headers["Authorization"] = "Bearer rd1." + controllerID + "." + secret
	response, err := handler.Handle(context.Background(), event)
	if err != nil || response.StatusCode != 200 || len(targets) != 1 || targets[0] != "companion:session.closed" {
		t.Fatalf("targets = %v, response = %#v, error = %v", targets, response, err)
	}
}

func TestPairFrameForwardsOpaquePayloadWithoutSuccessReply(t *testing.T) {
	pairID := uuid(2)
	sideB := PairSide{ConnectionID: "b", SideID: uuid(4)}
	pair := Pair{PairID: pairID, Locator: "123456", Status: "READY", SideA: PairSide{ConnectionID: "a", SideID: uuid(3)}, SideB: &sideB, ExpiresAt: 1000}
	var sent []struct {
		target  string
		message Message
	}
	handler := testHandler(&fakeStore{
		rateLimit: func(_ context.Context, _ string, action string, limit, _ int64) error {
			if action != "pair.frame" || limit != 120 {
				t.Fatalf("rate limit = %s/%d", action, limit)
			}
			return nil
		},
		pairByID: func(_ context.Context, id string, _ int64) (Pair, error) {
			if id != pairID {
				t.Fatalf("pair id = %s", id)
			}
			return pair, nil
		},
	}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		sent = append(sent, struct {
			target  string
			message Message
		}{target, message})
		return nil
	})
	response, err := handler.Handle(context.Background(), socketEvent("a", "pair.frame", envelope("pair.frame", map[string]any{
		"pairId": pairID, "seq": 1, "payload": "AQID", "future": map[string]any{"kept": true},
	})))
	if err != nil || response.Body != "" || len(sent) != 1 || sent[0].target != "b" || sent[0].message.Type != "pair.frame" {
		t.Fatalf("sent = %#v, response = %#v, error = %v", sent, response, err)
	}
	body := decodedMessageBody(t, sent[0].message)
	if body["payload"] != "AQID" || body["future"].(map[string]any)["kept"] != true {
		t.Fatalf("body = %#v", body)
	}
}

func TestSessionFrameUsesOnlySessionAuthority(t *testing.T) {
	session := Session{
		SessionID: uuid(7), LinkID: uuid(8), ControllerID: uuid(5), CompanionID: uuid(6),
		ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", ExpiresAt: 1000,
	}
	reads := 0
	var sent []struct {
		target  string
		message Message
	}
	handler := testHandler(&fakeStore{session: func(_ context.Context, id string, _ int64) (Session, error) {
		reads++
		if id != session.SessionID {
			t.Fatalf("session id = %s", id)
		}
		return session, nil
	}}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		if message.Type != "session.frame" {
			t.Fatalf("message = %#v", message)
		}
		sent = append(sent, struct {
			target  string
			message Message
		}{connectionID, message})
		return nil
	})
	for index, test := range []struct {
		from, to, payload string
	}{
		{"controller", "companion", "AQID"},
		{"companion", "controller", "BAUG"},
	} {
		response, err := handler.Handle(context.Background(), socketEvent(test.from, "session.frame", envelope("session.frame", map[string]any{
			"sessionId": session.SessionID, "seq": index + 1, "payload": test.payload, "future": test.from,
		})))
		if err != nil || response.Body != "" || len(sent) != index+1 || sent[index].target != test.to {
			t.Fatalf("sent = %#v, response = %#v, error = %v", sent, response, err)
		}
		body := decodedMessageBody(t, sent[index].message)
		if body["payload"] != test.payload || body["future"] != test.from {
			t.Fatalf("body = %#v", body)
		}
	}
	if reads != 2 {
		t.Fatalf("session reads = %d", reads)
	}
}

func TestSessionOpenCallbackFailureClosesCommittedSession(t *testing.T) {
	controllerID, companionID, sessionID := uuid(30), uuid(31), uuid(32)
	session := Session{
		SessionID: sessionID, LinkID: uuid(33), ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", ExpiresAt: 1000,
	}
	closeCalls := 0
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, ExpiresAt: 1000}, nil
		},
		openSession: func(context.Context, string, string, string, string, int64) (Session, error) {
			return session, nil
		},
		closeSession: func(context.Context, string, string, int64) (*CloseSessionResult, error) {
			closeCalls++
			closed := session
			closed.Status = "CLOSED"
			return &CloseSessionResult{Session: closed, ClosedNow: true}, nil
		},
	}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		if target == "controller" && message.Type == "session.opened" {
			return errors.New("callback failed")
		}
		return nil
	})
	response, err := handler.Handle(context.Background(), socketEvent("controller", "$default", envelope("session.open", map[string]any{"linkId": session.LinkID})))
	if err != nil || closeCalls != 1 {
		t.Fatalf("close calls = %d, response = %#v, error = %v", closeCalls, response, err)
	}
	if message := parseResponse(t, response); message.Type != "error" {
		t.Fatalf("message = %#v", message)
	}
}

func TestForeignSessionFrameGetsOneCorrelatedError(t *testing.T) {
	session := Session{SessionID: uuid(7), ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", ExpiresAt: 1000}
	var sent []Message
	handler := testHandler(&fakeStore{session: func(context.Context, string, int64) (Session, error) {
		return session, nil
	}}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		if target != "attacker" {
			t.Fatalf("target = %s", target)
		}
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("attacker", "session.frame", envelope("session.frame", map[string]any{
		"sessionId": session.SessionID, "seq": 1, "payload": "AQID",
	})))
	if err != nil || len(sent) != 1 || sent[0].Type != "error" || sent[0].ReplyTo != uuid(1) {
		t.Fatalf("sent = %#v, error = %v", sent, err)
	}
	if decodedMessageBody(t, sent[0])["code"] != string(protocol.Forbidden) {
		t.Fatalf("body = %#v", sent[0].Body)
	}
}

func TestInvalidFrameRetainsValidRequestCorrelation(t *testing.T) {
	var sent Message
	handler := testHandler(&fakeStore{}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		if target != "sender" {
			t.Fatalf("target = %s", target)
		}
		sent = message
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("sender", "session.frame", envelope("session.frame", map[string]any{
		"sessionId": uuid(40), "seq": 1, "payload": "AQ==",
	})))
	if err != nil || sent.Type != "error" || sent.ReplyTo != uuid(1) {
		t.Fatalf("message = %#v, error = %v", sent, err)
	}
}

func TestDefaultCommandReturnsNativeRouteResponse(t *testing.T) {
	rateCalls := 0
	posts := 0
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "pairing", AuthMode: "pairing", SourceKey: "source", ExpiresAt: 1000}, nil
		},
		rateLimit: func(_ context.Context, _ string, action string, limit, _ int64) error {
			rateCalls++
			if action != "pairing.message" || limit != 120 {
				t.Fatalf("rate limit = %s/%d", action, limit)
			}
			return nil
		},
	}, func(context.Context, string, Message, WebSocketEvent) error {
		posts++
		return nil
	})
	response, err := handler.Handle(context.Background(), socketEvent("pairing", "$default", envelope("system.hello", map[string]any{})))
	if err != nil || posts != 0 || rateCalls != 1 {
		t.Fatalf("posts = %d, rates = %d, response = %#v, error = %v", posts, rateCalls, response, err)
	}
	message := parseResponse(t, response)
	if message.Type != "ok" || message.ReplyTo != uuid(1) {
		t.Fatalf("message = %#v", message)
	}
}

func TestDefaultFailureAlsoUsesRouteResponse(t *testing.T) {
	posts := 0
	handler := testHandler(&fakeStore{}, func(context.Context, string, Message, WebSocketEvent) error {
		posts++
		return nil
	})
	response, err := handler.Handle(context.Background(), socketEvent("one", "$default", `{not-json`))
	if err != nil || posts != 0 {
		t.Fatalf("posts = %d, response = %#v, error = %v", posts, response, err)
	}
	if message := parseResponse(t, response); message.Type != "error" {
		t.Fatalf("message = %#v", message)
	}
}

func TestEndpointRevokeCutsOnlyActiveSessionAndReturnsNoCount(t *testing.T) {
	controllerID, companionID := uuid(70), uuid(71)
	session := Session{
		SessionID: uuid(73), LinkID: uuid(72), ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "CLOSED", ClosedAt: 100,
	}
	var sent []struct{ target, kind string }
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, ExpiresAt: 1000}, nil
		},
		revokeEndpoint: func(context.Context, string, int64) (RevokeEndpointResult, error) {
			return RevokeEndpointResult{Endpoint: Endpoint{EndpointID: controllerID}, Session: &CloseSessionResult{Session: session, ClosedNow: true}}, nil
		},
	}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		sent = append(sent, struct{ target, kind string }{target, message.Type})
		return nil
	})
	response, err := handler.Handle(context.Background(), socketEvent("controller", "$default", envelope("endpoint.revoke", map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ target, kind string }{{"controller", "session.closed"}, {"companion", "session.closed"}, {"companion", "link.revoked"}}
	if fmt.Sprint(sent) != fmt.Sprint(want) {
		t.Fatalf("sent = %#v", sent)
	}
	message := parseResponse(t, response)
	var body map[string]any
	_ = json.Unmarshal(message.Body, &body)
	result := body["result"].(map[string]any)
	if result["revoked"] != true || result["linksRevoked"] != nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestLinkGetDerivesEffectiveRevocationFromPeerEndpoint(t *testing.T) {
	controllerID, companionID, linkID := uuid(80), uuid(81), uuid(82)
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, ExpiresAt: 1000}, nil
		},
		link: func(context.Context, string) (*Link, error) {
			return &Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE"}, nil
		},
		getEndpoint: func(context.Context, string) (*Endpoint, error) {
			return &Endpoint{EndpointID: companionID, RevokedAt: 50}, nil
		},
	}, func(context.Context, string, Message, WebSocketEvent) error { return nil })
	response, err := handler.Handle(context.Background(), socketEvent("controller", "$default", envelope("link.get", map[string]any{"linkId": linkID})))
	if err != nil {
		t.Fatal(err)
	}
	message := parseResponse(t, response)
	var body map[string]any
	_ = json.Unmarshal(message.Body, &body)
	result := body["result"].(map[string]any)
	if result["status"] != "revoked" || result["revokedAt"] != float64(50) {
		t.Fatalf("result = %#v", result)
	}
}

func TestGonePeerClosesSessionBeforeReturningFrameError(t *testing.T) {
	session := Session{
		SessionID: uuid(90), ControllerID: uuid(91), CompanionID: uuid(92),
		ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", ExpiresAt: 1000,
	}
	closedSession := session
	closedSession.Status = "CLOSED"
	var sent []Message
	handler := testHandler(&fakeStore{
		session: func(context.Context, string, int64) (Session, error) { return session, nil },
		disconnect: func(_ context.Context, id string, _ int64) (*DisconnectResult, error) {
			if id != "companion" {
				t.Fatalf("disconnect = %s", id)
			}
			return &DisconnectResult{
				Connection: Connection{ConnectionID: id, AuthMode: "endpoint", EndpointID: session.CompanionID},
				Session:    &CloseSessionResult{Session: closedSession, ClosedNow: true},
			}, nil
		},
	}, func(_ context.Context, target string, message Message, _ WebSocketEvent) error {
		if target == "companion" {
			return apiError("GoneException")
		}
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", "session.frame", envelope("session.frame", map[string]any{
		"sessionId": session.SessionID, "seq": 1, "payload": "AQID",
	})))
	if err != nil || len(sent) != 2 || sent[0].Type != "session.closed" || sent[1].Type != "error" {
		t.Fatalf("sent = %#v, error = %v", sent, err)
	}
}

func TestLogsExcludeAuthorizationSourceAndCiphertext(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	handler := testHandlerWithLogger(&fakeStore{getEndpoint: func(context.Context, string) (*Endpoint, error) {
		return &Endpoint{CredentialHash: strings.Repeat("B", 43)}, nil
	}}, func(context.Context, string, Message, WebSocketEvent) error { return nil }, logger)
	event := socketEvent("one", "$connect", "")
	event.Headers["Authorization"] = "Bearer rd1." + uuid(99) + "." + strings.Repeat("A", 43)
	_, _ = handler.Handle(context.Background(), event)
	logged := output.String()
	if !strings.Contains(logged, "connect-rejected") {
		t.Fatalf("expected rejection log, got %s", logged)
	}
	for _, forbidden := range []string{event.Headers["Authorization"], "203.0.113.42", strings.Repeat("A", 43)} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("sensitive value logged: %q in %s", forbidden, logged)
		}
	}
}

func TestReciprocalCommitsExposeOnlyRoutingMetadata(t *testing.T) {
	a := PairCommit{ConnectionID: "a", SideID: uuid(3), LinkID: uuid(5), Self: PairEndpointCommit{EndpointID: uuid(6), Role: protocol.Controller, CredentialHash: strings.Repeat("a", 43)}, Peer: PairIdentity{EndpointID: uuid(7), Role: protocol.Companion}}
	b := PairCommit{ConnectionID: "b", SideID: uuid(4), LinkID: uuid(5), Self: PairEndpointCommit{EndpointID: uuid(7), Role: protocol.Companion, CredentialHash: strings.Repeat("b", 43)}, Peer: PairIdentity{EndpointID: uuid(6), Role: protocol.Controller}}
	if !ReciprocalCommits(a, b) || !SameCommit(a, a) {
		t.Fatal("valid commits rejected")
	}
	link, err := LinkFromCommits(a, b, 100)
	if err != nil || link.LinkID != uuid(5) || link.ControllerID != uuid(6) || link.CompanionID != uuid(7) || link.Status != "ACTIVE" {
		t.Fatalf("link = %#v, error = %v", link, err)
	}
	b.Self.EndpointID = a.Self.EndpointID
	if ReciprocalCommits(a, b) {
		t.Fatal("self-link accepted")
	}
}
