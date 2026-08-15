package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var unexpected = errors.New("unexpected store call")

type fakeStore struct {
	getEndpoint    func(context.Context, string) (*Endpoint, error)
	connect        func(context.Context, Connection, string) error
	disconnect     func(context.Context, string) (*Connection, error)
	connection     func(context.Context, string, int64) (Connection, error)
	rateLimit      func(context.Context, string, string, int64, int64) error
	createPair     func(context.Context, Pair) error
	pairByID       func(context.Context, string, int64) (Pair, error)
	pairByLocator  func(context.Context, string, int64) (Pair, error)
	joinPair       func(context.Context, string, PairSide, int64) (Pair, error)
	commitPair     func(context.Context, string, PairCommit, int64) (CommitPairResult, error)
	cancelPair     func(context.Context, string, string, int64) (*Pair, error)
	link           func(context.Context, string) (*Link, error)
	revokeLink     func(context.Context, string, string, int64) (Link, error)
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
func (f *fakeStore) Connect(ctx context.Context, c Connection, hash string) error {
	if f.connect == nil {
		return unexpected
	}
	return f.connect(ctx, c, hash)
}
func (f *fakeStore) Disconnect(ctx context.Context, id string) (*Connection, error) {
	if f.disconnect == nil {
		return nil, unexpected
	}
	return f.disconnect(ctx, id)
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
func (f *fakeStore) PairByLocator(ctx context.Context, locator string, now int64) (Pair, error) {
	if f.pairByLocator == nil {
		return Pair{}, unexpected
	}
	return f.pairByLocator(ctx, locator, now)
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
func (f *fakeStore) RevokeLink(ctx context.Context, linkID, endpointID string, now int64) (Link, error) {
	if f.revokeLink == nil {
		return Link{}, unexpected
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

type fakeDynamo struct {
	get      func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	delete   func(*dynamodb.DeleteItemInput) (*dynamodb.DeleteItemOutput, error)
	update   func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
	transact func(*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error)
	query    func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error)
}

func (f *fakeDynamo) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if f.get == nil {
		return nil, unexpected
	}
	return f.get(input)
}
func (f *fakeDynamo) DeleteItem(_ context.Context, input *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	if f.delete == nil {
		return nil, unexpected
	}
	return f.delete(input)
}
func (f *fakeDynamo) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if f.update == nil {
		return nil, unexpected
	}
	return f.update(input)
}
func (f *fakeDynamo) TransactWriteItems(_ context.Context, input *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	if f.transact == nil {
		return nil, unexpected
	}
	return f.transact(input)
}
func (f *fakeDynamo) Query(_ context.Context, input *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	if f.query == nil {
		return nil, unexpected
	}
	return f.query(input)
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

func socketEvent(connectionID string, body ...string) WebSocketEvent {
	event := WebSocketEvent{RequestContext: WebSocketRequestContext{
		RouteKey: "$connect", ConnectionID: connectionID, DomainName: "example.invalid", Stage: "v1",
		Identity: SocketIdentity{SourceIP: "203.0.113.42"}, Authorizer: map[string]any{"authMode": "pairing", "endpointId": ""},
	}}
	if len(body) != 0 {
		event.Body, event.RequestContext.RouteKey = body[0], "$default"
	}
	return event
}

func testHandler(store Store, post Post) *Handler {
	value := 10
	return NewHandler(HandlerDependencies{
		Store: store, Post: post, Now: func() int64 { return 100 },
		ID:     func() string { result := uuid(value); value++; return result },
		Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
}

func avItem(t *testing.T, kind, id string, value any) map[string]types.AttributeValue {
	t.Helper()
	item, err := marshalItem(kind, id, value)
	if err != nil {
		t.Fatal(err)
	}
	return item
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

func TestAuthorizerHashesRawBearerSecret(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(bytesOf(32, 7))
	digest := sha256.Sum256(bytesOf(32, 7))
	credentialHash := base64.RawURLEncoding.EncodeToString(digest[:])
	endpointID := uuid(9)
	authorize := NewAuthorizer(&fakeStore{getEndpoint: func(context.Context, string) (*Endpoint, error) {
		return &Endpoint{EndpointID: endpointID, CredentialHash: credentialHash, Role: protocol.Controller, CreatedAt: 1, UpdatedAt: 1}, nil
	}})
	result, err := authorize(context.Background(), AuthorizerEvent{
		Headers: map[string]string{"Authorization": "Bearer rd1." + endpointID + "." + secret}, MethodARN: "arn",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Context["authMode"] != "endpoint" || result.Context["credentialHash"] != credentialHash {
		t.Fatalf("context = %#v", result.Context)
	}
	_, err = authorize(context.Background(), AuthorizerEvent{
		Headers: map[string]string{"Authorization": "Bearer rd1." + endpointID + "." + base64.RawURLEncoding.EncodeToString(bytesOf(32, 8))}, MethodARN: "arn",
	})
	if !errors.Is(err, errUnauthorized) {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectStoresSourceHashNotRawIP(t *testing.T) {
	var saved Connection
	handler := testHandler(&fakeStore{connect: func(_ context.Context, connection Connection, _ string) error {
		saved = connection
		return nil
	}}, func(context.Context, string, Message, WebSocketEvent) error { return nil })
	response, err := handler.Handle(context.Background(), socketEvent("one"))
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("response = %#v, %v", response, err)
	}
	encoded, _ := json.Marshal(saved)
	if saved.SourceKey != SourceKey("203.0.113.42") || strings.Contains(string(encoded), "203.0.113.42") {
		t.Fatalf("saved = %#v", saved)
	}
}

func TestPairRelayForwardsOpaqueCiphertext(t *testing.T) {
	connection := Connection{ConnectionID: "a", AuthMode: "pairing", SourceKey: "source", PairingID: uuid(2), ConnectedAt: 1, ExpiresAt: 1000}
	sideB := PairSide{ConnectionID: "b", SideID: uuid(4)}
	pair := Pair{PairID: uuid(2), Locator: "123456", Status: "READY", SideA: PairSide{ConnectionID: "a", SideID: uuid(3)}, SideB: &sideB, Version: 2, ExpiresAt: 1000}
	var sent []struct {
		connectionID string
		message      Message
	}
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) { return connection, nil },
		pairByID:   func(context.Context, string, int64) (Pair, error) { return pair, nil },
	}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		sent = append(sent, struct {
			connectionID string
			message      Message
		}{connectionID, message})
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("a", envelope("relay.frame", map[string]any{
		"channel": "pair", "channelId": pair.PairID, "seq": 1, "payload": "AQID", "future": map[string]any{"kept": true},
	})))
	if err != nil {
		t.Fatal(err)
	}
	frame := decodedMessageBody(t, sent[0].message)
	if sent[0].connectionID != "b" || frame["payload"] != "AQID" || frame["future"].(map[string]any)["kept"] != true || sent[len(sent)-1].message.Type != "ok" {
		t.Fatalf("sent = %#v", sent)
	}
}

func TestSessionRelayPreservesAdditiveFields(t *testing.T) {
	controllerID, companionID := uuid(5), uuid(6)
	session := Session{SessionID: uuid(7), LinkID: uuid(8), ControllerID: controllerID, CompanionID: companionID, ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1000}
	connection := Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, SourceKey: "source", SessionID: session.SessionID, ConnectedAt: 1, ExpiresAt: 1000}
	endpoints := map[string]*Endpoint{
		controllerID: {EndpointID: controllerID, Role: protocol.Controller, ConnectionID: "controller"},
		companionID:  {EndpointID: companionID, Role: protocol.Companion, ConnectionID: "companion"},
	}
	var sent []struct {
		connectionID string
		message      Message
	}
	handler := testHandler(&fakeStore{
		connection:  func(context.Context, string, int64) (Connection, error) { return connection, nil },
		session:     func(context.Context, string, int64) (Session, error) { return session, nil },
		getEndpoint: func(_ context.Context, id string) (*Endpoint, error) { return endpoints[id], nil },
		link: func(context.Context, string) (*Link, error) {
			return &Link{LinkID: session.LinkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE", ActiveSessionID: session.SessionID}, nil
		},
	}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		sent = append(sent, struct {
			connectionID string
			message      Message
		}{connectionID, message})
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", envelope("relay.frame", map[string]any{
		"channel": "session", "channelId": session.SessionID, "seq": 1, "payload": "AQID", "future": map[string]any{"kept": true},
	})))
	if err != nil {
		t.Fatal(err)
	}
	frame := decodedMessageBody(t, sent[0].message)
	if sent[0].connectionID != "companion" || frame["future"].(map[string]any)["kept"] != true || sent[len(sent)-1].message.Type != "ok" {
		t.Fatalf("sent = %#v", sent)
	}
}

func TestReciprocalCommitsExposeOnlyRoutingMetadata(t *testing.T) {
	a := PairCommit{ConnectionID: "a", SideID: uuid(3), LinkID: uuid(5), Self: PairEndpointCommit{EndpointID: uuid(6), Role: protocol.Controller, CredentialHash: strings.Repeat("a", 43)}, Peer: PairIdentity{EndpointID: uuid(7), Role: protocol.Companion}}
	b := PairCommit{ConnectionID: "b", SideID: uuid(4), LinkID: uuid(5), Self: PairEndpointCommit{EndpointID: uuid(7), Role: protocol.Companion, CredentialHash: strings.Repeat("b", 43)}, Peer: PairIdentity{EndpointID: uuid(6), Role: protocol.Controller}}
	if !ReciprocalCommits(a, b) || !SameCommit(a, a) {
		t.Fatal("valid commits rejected")
	}
	link, err := LinkFromCommits(a, b, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(link, Link{LinkID: uuid(5), ControllerID: uuid(6), CompanionID: uuid(7), Status: "ACTIVE", CreatedAt: 100}) {
		t.Fatalf("link = %#v", link)
	}
	b.Self.EndpointID = a.Self.EndpointID
	if ReciprocalCommits(a, b) {
		t.Fatal("self-link accepted")
	}
}

func TestConnectTransactionBoundToAuthorizerHash(t *testing.T) {
	var input *dynamodb.TransactWriteItemsInput
	store := NewDynamoStore("table", &fakeDynamo{transact: func(value *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
		input = value
		return &dynamodb.TransactWriteItemsOutput{}, nil
	}})
	err := store.Connect(context.Background(), Connection{ConnectionID: "connection", AuthMode: "endpoint", EndpointID: uuid(6), SourceKey: "source", ConnectedAt: 1, ExpiresAt: 2}, "validated-hash")
	if err != nil {
		t.Fatal(err)
	}
	update := input.TransactItems[1].Update
	if !strings.Contains(*update.ConditionExpression, "credentialHash = :credentialHash") {
		t.Fatalf("condition = %s", *update.ConditionExpression)
	}
	var hash string
	if err := attributevalue.Unmarshal(update.ExpressionAttributeValues[":credentialHash"], &hash); err != nil {
		t.Fatal(err)
	}
	if hash != "validated-hash" {
		t.Fatalf("hash = %s", hash)
	}
}

func TestOpenSessionConnectionUpdatesUseOnlySessionID(t *testing.T) {
	controllerID, companionID, linkID, sessionID := uuid(10), uuid(11), uuid(12), uuid(13)
	items := map[string]map[string]types.AttributeValue{
		"LINK#" + linkID:           avItem(t, "link", linkID, Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE"}),
		"ENDPOINT#" + controllerID: avItem(t, "endpoint", controllerID, Endpoint{EndpointID: controllerID, Role: protocol.Controller, ConnectionID: "controller"}),
		"ENDPOINT#" + companionID:  avItem(t, "endpoint", companionID, Endpoint{EndpointID: companionID, Role: protocol.Companion, ConnectionID: "companion"}),
		"CONNECTION#controller":    avItem(t, "connection", "controller", Connection{ConnectionID: "controller"}),
		"CONNECTION#companion":     avItem(t, "connection", "companion", Connection{ConnectionID: "companion"}),
	}
	var transaction *dynamodb.TransactWriteItemsInput
	store := NewDynamoStore("table", &fakeDynamo{
		get: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: items[input.Key["pk"].(*types.AttributeValueMemberS).Value]}, nil
		},
		transact: func(input *dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			transaction = input
			return &dynamodb.TransactWriteItemsOutput{}, nil
		},
	})
	if _, err := store.OpenSession(context.Background(), linkID, controllerID, "controller", sessionID, 100); err != nil {
		t.Fatal(err)
	}
	if transaction == nil || len(transaction.TransactItems) != 6 {
		t.Fatalf("transaction = %#v", transaction)
	}
	for _, operation := range transaction.TransactItems[4:] {
		values := operation.Update.ExpressionAttributeValues
		if len(values) != 1 || values[":sessionId"] == nil {
			t.Fatalf("connection values = %#v", values)
		}
	}
}

func TestOpenSessionPropagatesLinkRereadFailure(t *testing.T) {
	controllerID, companionID, linkID, staleID := uuid(14), uuid(15), uuid(16), uuid(17)
	link := Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE"}
	controller := Endpoint{EndpointID: controllerID, Role: protocol.Controller, ConnectionID: "controller"}
	companion := Endpoint{EndpointID: companionID, Role: protocol.Companion, ConnectionID: "companion", ActiveSessionID: staleID}
	backendErr := errors.New("link reread failed")
	linkReads := 0
	store := NewDynamoStore("table", &fakeDynamo{
		get: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			switch pk := input.Key["pk"].(*types.AttributeValueMemberS).Value; pk {
			case "LINK#" + linkID:
				linkReads++
				if linkReads == 2 {
					return nil, backendErr
				}
				return &dynamodb.GetItemOutput{Item: avItem(t, "link", linkID, link)}, nil
			case "ENDPOINT#" + controllerID:
				return &dynamodb.GetItemOutput{Item: avItem(t, "endpoint", controllerID, controller)}, nil
			case "ENDPOINT#" + companionID:
				return &dynamodb.GetItemOutput{Item: avItem(t, "endpoint", companionID, companion)}, nil
			case "CONNECTION#controller":
				return &dynamodb.GetItemOutput{Item: avItem(t, "connection", "controller", Connection{ConnectionID: "controller"})}, nil
			case "CONNECTION#companion":
				return &dynamodb.GetItemOutput{Item: avItem(t, "connection", "companion", Connection{ConnectionID: "companion"})}, nil
			case "SESSION#" + staleID:
				return &dynamodb.GetItemOutput{}, nil
			default:
				t.Fatalf("unexpected read %s", pk)
				return nil, nil
			}
		},
		update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return &dynamodb.UpdateItemOutput{}, nil
		},
	})
	_, err := store.OpenSession(context.Background(), linkID, controllerID, "controller", uuid(18), 100)
	if !errors.Is(err, backendErr) {
		t.Fatalf("error = %v", err)
	}
}

func TestPairCancellationRejectsActivationRaces(t *testing.T) {
	pair := Pair{PairID: uuid(10), Locator: "123456", Status: "ACTIVE", SideA: PairSide{ConnectionID: "a", SideID: uuid(11)}, SideB: &PairSide{ConnectionID: "b", SideID: uuid(12)}, Version: 4, ExpiresAt: 1000}
	storeWithStates := func(states []Pair) *DynamoStore {
		reads := 0
		return NewDynamoStore("table", &fakeDynamo{
			get: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				pk := input.Key["pk"].(*types.AttributeValueMemberS).Value
				if pk == "PAIRID#"+pair.PairID {
					return &dynamodb.GetItemOutput{Item: avItem(t, "pairid", pair.PairID, pairPointer{PairID: pair.PairID, Locator: pair.Locator, ExpiresAt: pair.ExpiresAt})}, nil
				}
				current := states[min(reads, len(states)-1)]
				reads++
				return &dynamodb.GetItemOutput{Item: avItem(t, "pair", pair.Locator, current)}, nil
			},
			update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
				return nil, apiError("ConditionalCheckFailedException")
			},
		})
	}
	assertConflict := func(err error) {
		var service *ServiceError
		if !errors.As(err, &service) || service.Code != protocol.Conflict {
			t.Fatalf("error = %v", err)
		}
	}
	_, err := storeWithStates([]Pair{pair}).CancelPair(context.Background(), pair.PairID, "a", 100)
	assertConflict(err)
	half := pair
	half.Status, half.Version = "HALF_COMMITTED", 3
	_, err = storeWithStates([]Pair{half, pair}).CancelPair(context.Background(), pair.PairID, "a", 100)
	assertConflict(err)
}

func TestEndpointRevocationPersistsBeforeEnumeration(t *testing.T) {
	endpoint := Endpoint{EndpointID: uuid(13), CredentialHash: strings.Repeat("a", 43), Role: protocol.Controller, CreatedAt: 1, UpdatedAt: 1}
	var operations []string
	store := NewDynamoStore("table", &fakeDynamo{
		get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: avItem(t, "endpoint", endpoint.EndpointID, endpoint)}, nil
		},
		update: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			operations = append(operations, "revoke")
			return &dynamodb.UpdateItemOutput{}, nil
		},
		query: func(*dynamodb.QueryInput) (*dynamodb.QueryOutput, error) {
			operations = append(operations, "query")
			return &dynamodb.QueryOutput{}, nil
		},
	})
	if _, err := store.RevokeEndpoint(context.Background(), endpoint.EndpointID, 100); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operations, []string{"revoke", "query"}) {
		t.Fatalf("operations = %v", operations)
	}
}

func TestClosedSessionsRetryPointerCleanup(t *testing.T) {
	session := Session{SessionID: uuid(20), LinkID: uuid(21), ControllerID: uuid(22), CompanionID: uuid(23), ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 2}
	stored := session
	var updates []string
	store := NewDynamoStore("table", &fakeDynamo{
		get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: avItem(t, "session", session.SessionID, stored)}, nil
		},
		update: func(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			pk := input.Key["pk"].(*types.AttributeValueMemberS).Value
			updates = append(updates, pk+":"+*input.UpdateExpression)
			if pk == "SESSION#"+session.SessionID {
				stored.Status, stored.ClosedAt = "CLOSED", 10
			}
			return &dynamodb.UpdateItemOutput{}, nil
		},
	})
	first, err := store.CloseSession(context.Background(), session.SessionID, session.ControllerID, 10)
	if err != nil || !first.ClosedNow {
		t.Fatalf("first = %#v, %v", first, err)
	}
	second, err := store.CloseSession(context.Background(), session.SessionID, session.ControllerID, 11)
	if err != nil || second.ClosedNow {
		t.Fatalf("second = %#v, %v", second, err)
	}
	count := 0
	for _, update := range updates {
		if strings.Contains(update, "REMOVE activeSessionId") {
			count++
		}
	}
	if count != 4 {
		t.Fatalf("active-session cleanup count = %d; %v", count, updates)
	}
}

func TestSessionCleanupPropagatesDynamoFailure(t *testing.T) {
	session := Session{SessionID: uuid(24), LinkID: uuid(25), ControllerID: uuid(26), CompanionID: uuid(27), ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "CLOSED", CreatedAt: 1, ExpiresAt: 2}
	store := NewDynamoStore("table", &fakeDynamo{
		get: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			return &dynamodb.GetItemOutput{Item: avItem(t, "session", session.SessionID, session)}, nil
		},
		update: func(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			if input.Key["pk"].(*types.AttributeValueMemberS).Value == "LINK#"+session.LinkID {
				return nil, errors.New("cleanup failed")
			}
			return &dynamodb.UpdateItemOutput{}, nil
		},
	})
	_, err := store.CloseSession(context.Background(), session.SessionID, "", 10)
	if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("error = %v", err)
	}
}

func TestRevokedLinkCannotRelayActiveSession(t *testing.T) {
	controllerID, companionID := uuid(30), uuid(31)
	session := Session{SessionID: uuid(32), LinkID: uuid(33), ControllerID: controllerID, CompanionID: companionID, ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1000}
	connection := Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, SourceKey: "source", SessionID: session.SessionID, ConnectedAt: 1, ExpiresAt: 1000}
	endpoints := map[string]*Endpoint{
		controllerID: {EndpointID: controllerID, CredentialHash: strings.Repeat("a", 43), Role: protocol.Controller, ConnectionID: "controller", CreatedAt: 1, UpdatedAt: 1},
		companionID:  {EndpointID: companionID, CredentialHash: strings.Repeat("b", 43), Role: protocol.Companion, ConnectionID: "companion", CreatedAt: 1, UpdatedAt: 1},
	}
	var sent []struct {
		connectionID string
		message      Message
	}
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) { return connection, nil },
		session:    func(context.Context, string, int64) (Session, error) { return session, nil },
		link: func(context.Context, string) (*Link, error) {
			return &Link{LinkID: session.LinkID, ControllerID: controllerID, CompanionID: companionID, Status: "REVOKED", ActiveSessionID: session.SessionID, CreatedAt: 1}, nil
		},
		getEndpoint: func(_ context.Context, id string) (*Endpoint, error) { return endpoints[id], nil },
		closeSession: func(context.Context, string, string, int64) (*CloseSessionResult, error) {
			closed := session
			closed.Status = "CLOSED"
			return &CloseSessionResult{Session: closed, ClosedNow: true}, nil
		},
	}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		sent = append(sent, struct {
			connectionID string
			message      Message
		}{connectionID, message})
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", envelope("relay.frame", map[string]any{"channel": "session", "channelId": session.SessionID, "seq": 1, "payload": "AQID"})))
	if err != nil {
		t.Fatal(err)
	}
	for _, output := range sent {
		if output.connectionID == "companion" && output.message.Type == "relay.frame" {
			t.Fatal("ciphertext forwarded over revoked link")
		}
	}
	if sent[len(sent)-1].message.Body.(map[string]any)["code"] != protocol.Forbidden {
		t.Fatalf("last = %#v", sent[len(sent)-1])
	}
}

func TestPairJoinReportsOfflineWhenCreatorGone(t *testing.T) {
	pair := Pair{PairID: uuid(50), Locator: "123456", Status: "READY", SideA: PairSide{ConnectionID: "creator", SideID: uuid(51)}, SideB: &PairSide{ConnectionID: "joiner", SideID: uuid(52)}, Version: 2, ExpiresAt: 1000}
	joiner := Connection{ConnectionID: "joiner", AuthMode: "pairing", SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1000}
	var sent []Message
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) { return joiner, nil },
		rateLimit:  func(context.Context, string, string, int64, int64) error { return nil },
		joinPair:   func(context.Context, string, PairSide, int64) (Pair, error) { return pair, nil },
		disconnect: func(context.Context, string) (*Connection, error) {
			return &Connection{ConnectionID: "creator", AuthMode: "pairing", SourceKey: "source", PairingID: pair.PairID, ConnectedAt: 1, ExpiresAt: 1000}, nil
		},
		cancelPair: func(context.Context, string, string, int64) (*Pair, error) {
			closed := pair
			closed.Status = "CLOSED"
			return &closed, nil
		},
	}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		if connectionID == "creator" {
			return apiError("GoneException")
		}
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("joiner", envelope("pair.join", map[string]any{"locator": pair.Locator})))
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range sent {
		if message.Type == "ok" {
			t.Fatal("join unexpectedly succeeded")
		}
	}
	if sent[len(sent)-1].Body.(map[string]any)["code"] != protocol.PeerOffline {
		t.Fatalf("sent = %#v", sent)
	}
}

func TestSessionOpenClosesWhenCompanionGone(t *testing.T) {
	controllerID, companionID := uuid(61), uuid(62)
	session := Session{SessionID: uuid(63), LinkID: uuid(64), ControllerID: controllerID, CompanionID: companionID, ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1000}
	var sent []Message
	closed := false
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1000}, nil
		},
		openSession: func(context.Context, string, string, string, string, int64) (Session, error) { return session, nil },
		disconnect: func(context.Context, string) (*Connection, error) {
			return &Connection{ConnectionID: "companion", AuthMode: "endpoint", EndpointID: companionID, SourceKey: "source", SessionID: session.SessionID, ConnectedAt: 1, ExpiresAt: 1000}, nil
		},
		closeSession: func(context.Context, string, string, int64) (*CloseSessionResult, error) {
			closedNow := !closed
			closed = true
			value := session
			value.Status = "CLOSED"
			return &CloseSessionResult{Session: value, ClosedNow: closedNow}, nil
		},
	}, func(_ context.Context, connectionID string, message Message, _ WebSocketEvent) error {
		if connectionID == "companion" {
			return apiError("GoneException")
		}
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", envelope("session.open", map[string]any{"linkId": session.LinkID})))
	if err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("session not closed")
	}
	foundClosed := false
	for _, message := range sent {
		if message.Type == "session.closed" {
			foundClosed = true
		}
		if message.Type == "ok" {
			t.Fatal("open unexpectedly succeeded")
		}
	}
	if !foundClosed || sent[len(sent)-1].Body.(map[string]any)["code"] != protocol.PeerOffline {
		t.Fatalf("sent = %#v", sent)
	}
}

func TestEndpointRevocationEmitsSessionBeforeLink(t *testing.T) {
	controllerID, companionID := uuid(70), uuid(71)
	link := Link{LinkID: uuid(72), ControllerID: controllerID, CompanionID: companionID, Status: "REVOKED", CreatedAt: 1, RevokedAt: 100}
	session := Session{SessionID: uuid(73), LinkID: link.LinkID, ControllerID: controllerID, CompanionID: companionID, ControllerConnectionID: "controller", CompanionConnectionID: "companion", Status: "CLOSED", CreatedAt: 1, ExpiresAt: 1000, ClosedAt: 100}
	var sent []Message
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: controllerID, SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1000}, nil
		},
		revokeEndpoint: func(context.Context, string, int64) (RevokeEndpointResult, error) {
			return RevokeEndpointResult{Endpoint: Endpoint{EndpointID: controllerID}, Links: []Link{link}, Sessions: []Session{session}}, nil
		},
		getEndpoint: func(_ context.Context, id string) (*Endpoint, error) {
			if id == companionID {
				return &Endpoint{EndpointID: id, ConnectionID: "companion"}, nil
			}
			return nil, nil
		},
	}, func(_ context.Context, _ string, message Message, _ WebSocketEvent) error {
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", envelope("endpoint.revoke", map[string]any{})))
	if err != nil {
		t.Fatal(err)
	}
	closedIndex, revokedIndex := -1, -1
	for i, message := range sent {
		if message.Type == "session.closed" && closedIndex < 0 {
			closedIndex = i
		}
		if message.Type == "link.revoked" && revokedIndex < 0 {
			revokedIndex = i
		}
	}
	if closedIndex < 0 || revokedIndex < 0 || closedIndex >= revokedIndex {
		t.Fatalf("event order = %#v", sent)
	}
}

func TestSessionCloseIsIdempotentSuccess(t *testing.T) {
	endpointID := uuid(90)
	var sent []Message
	handler := testHandler(&fakeStore{
		connection: func(context.Context, string, int64) (Connection, error) {
			return Connection{ConnectionID: "controller", AuthMode: "endpoint", EndpointID: endpointID, SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1000}, nil
		},
		closeSession: func(context.Context, string, string, int64) (*CloseSessionResult, error) { return nil, nil },
	}, func(_ context.Context, _ string, message Message, _ WebSocketEvent) error {
		sent = append(sent, message)
		return nil
	})
	_, err := handler.Handle(context.Background(), socketEvent("controller", envelope("session.close", map[string]any{"sessionId": uuid(99)})))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(sent[len(sent)-1])
	reply, err := protocol.ParseServer(encoded)
	if err != nil || reply.Type != "ok" {
		t.Fatalf("reply = %s, %v", encoded, err)
	}
	var body map[string]any
	_ = json.Unmarshal(reply.Body, &body)
	if body["requestType"] != "session.close" || body["result"].(map[string]any)["closed"] != true {
		t.Fatalf("body = %#v", body)
	}
}

func bytesOf(length int, value byte) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = value
	}
	return result
}
