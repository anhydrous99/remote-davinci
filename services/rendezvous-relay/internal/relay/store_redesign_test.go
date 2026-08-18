package relay

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type storageDynamo struct {
	items        map[string]map[string]types.AttributeValue
	reads        int
	updates      []*dynamodb.UpdateItemInput
	transactions []*dynamodb.TransactWriteItemsInput
	getItem      func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	updateItem   func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error)
	transact     func(*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error)
}

func (d *storageDynamo) GetItem(_ context.Context, input *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	d.reads++
	if d.getItem != nil {
		return d.getItem(input)
	}
	return &dynamodb.GetItemOutput{Item: d.items[storagePK(input.Key)]}, nil
}

func (d *storageDynamo) UpdateItem(_ context.Context, input *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	d.updates = append(d.updates, input)
	if d.updateItem != nil {
		return d.updateItem(input)
	}
	return &dynamodb.UpdateItemOutput{}, nil
}

func (d *storageDynamo) TransactWriteItems(_ context.Context, input *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	d.transactions = append(d.transactions, input)
	if d.transact != nil {
		return d.transact(input)
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func storagePK(key map[string]types.AttributeValue) string {
	return key["pk"].(*types.AttributeValueMemberS).Value
}

func storageItem(t *testing.T, kind, id string, value any) map[string]types.AttributeValue {
	t.Helper()
	item, err := marshalItem(kind, id, value)
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func storageUUID(value string) string { return "00000000-0000-4000-8000-" + value }

func TestConditionalFailureInspectsTransactionCancellationReasons(t *testing.T) {
	reason := func(code string) types.CancellationReason { return types.CancellationReason{Code: &code} }
	for _, test := range []struct {
		name    string
		err     error
		matched bool
	}{
		{"direct condition", &types.ConditionalCheckFailedException{}, true},
		{"condition and none", &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{reason("ConditionalCheckFailed"), reason("None")}}, true},
		{"condition and throttle", &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{reason("ConditionalCheckFailed"), reason("ThrottlingError")}}, false},
		{"transaction conflict", &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{reason("TransactionConflict")}}, false},
		{"missing reasons", &types.TransactionCanceledException{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := conditionalFailure(test.err); got != test.matched {
				t.Fatalf("conditionalFailure() = %t, want %t", got, test.matched)
			}
		})
	}
}

func TestPairStorageUsesPairIDAndLocatorKeys(t *testing.T) {
	pair := Pair{
		PairID: storageUUID("000000000001"), Locator: "123456", Status: "OPEN",
		SideA:     PairSide{ConnectionID: "connection", SideID: storageUUID("000000000002")},
		ExpiresAt: 400,
	}
	db := &storageDynamo{}
	store := NewDynamoStore("table", db)
	if err := store.CreatePair(context.Background(), pair); err != nil {
		t.Fatal(err)
	}
	transaction := db.transactions[0].TransactItems
	if got := storagePK(transaction[0].Put.Item); got != "PAIR#"+pair.PairID {
		t.Fatalf("pair key = %s", got)
	}
	if got := storagePK(transaction[1].Put.Item); got != "LOCATOR#"+pair.Locator {
		t.Fatalf("locator key = %s", got)
	}
	if _, exists := transaction[0].Put.Item["version"]; exists {
		t.Fatal("pair unexpectedly persisted a version")
	}
}

func TestPairAndSessionHotPathsEachUseOneStrongRead(t *testing.T) {
	pairID, sessionID := storageUUID("000000000003"), storageUUID("000000000004")
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"PAIR#" + pairID: storageItem(t, "pair", pairID, Pair{
			PairID: pairID, Locator: "123456", Status: "READY", ExpiresAt: 1_000,
		}),
		"SESSION#" + sessionID: storageItem(t, "session", sessionID, Session{
			SessionID: sessionID, Status: "ACTIVE", ExpiresAt: 1_000,
		}),
	}}
	store := NewDynamoStore("table", db)
	if _, err := store.PairByID(context.Background(), pairID, 100); err != nil {
		t.Fatal(err)
	}
	if db.reads != 1 {
		t.Fatalf("pair reads = %d", db.reads)
	}
	if _, err := store.Session(context.Background(), sessionID, 100); err != nil {
		t.Fatal(err)
	}
	if db.reads != 2 || len(db.transactions) != 0 {
		t.Fatalf("total reads = %d, transactions = %d", db.reads, len(db.transactions))
	}
}

func TestConnectionAuthorityUsesOneStrongRecordRead(t *testing.T) {
	connection := Connection{
		ConnectionID: "controller", AuthMode: "endpoint", EndpointID: storageUUID("000000000006"),
		SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1_000,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"CONNECTION#controller": storageItem(t, "connection", "controller", connection),
	}}
	got, err := NewDynamoStore("table", db).Connection(context.Background(), "controller", 100)
	if err != nil || got.EndpointID != connection.EndpointID || db.reads != 1 {
		t.Fatalf("connection = %#v, reads = %d, error = %v", got, db.reads, err)
	}
}

func TestEndpointWriteIsConditionalUpsert(t *testing.T) {
	endpoint := Endpoint{
		EndpointID: storageUUID("000000000005"), CredentialHash: "hash", Role: protocol.Controller,
		CreatedAt: 10, UpdatedAt: 20,
	}
	write, err := NewDynamoStore("table", &storageDynamo{}).endpointWrite(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if write.Update == nil || write.Put != nil || write.ConditionCheck != nil {
		t.Fatalf("write = %#v", write)
	}
	update := *write.Update.UpdateExpression
	for _, field := range []string{"endpointId", "credentialHash", "#role", "createdAt", "updatedAt", "#kind"} {
		if !strings.Contains(update, field+" = if_not_exists("+field) {
			t.Fatalf("update does not preserve %s: %s", field, update)
		}
	}
	condition := *write.Update.ConditionExpression
	for _, clause := range []string{"attribute_not_exists(pk)", "credentialHash = :credentialHash", "#role = :role", "attribute_not_exists(revokedAt)"} {
		if !strings.Contains(condition, clause) {
			t.Fatalf("condition does not contain %q: %s", clause, condition)
		}
	}
}

func TestRotateEndpointFencesExpectedConnection(t *testing.T) {
	db := &storageDynamo{updateItem: func(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
		if !strings.Contains(*input.ConditionExpression, "connectionId = :connectionId") ||
			input.ExpressionAttributeValues[":connectionId"].(*types.AttributeValueMemberS).Value != "old" {
			t.Fatalf("rotate condition = %#v", input)
		}
		return nil, &types.ConditionalCheckFailedException{}
	}}
	err := NewDynamoStore("table", db).RotateEndpoint(context.Background(), storageUUID("000000000007"), "old", strings.Repeat("a", 43), 100)
	var service *ServiceError
	if !errors.As(err, &service) || service.Code != protocol.Unauthenticated {
		t.Fatalf("error = %#v", err)
	}
}

func TestOpenSessionLocksOnlySessionLinkAndEndpoints(t *testing.T) {
	controllerID, companionID := storageUUID("000000000010"), storageUUID("000000000011")
	linkID, sessionID := storageUUID("000000000012"), storageUUID("000000000013")
	link := Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE", CreatedAt: 1}
	controller := Endpoint{EndpointID: controllerID, CredentialHash: strings.Repeat("a", 43), Role: protocol.Controller, ConnectionID: "controller", CreatedAt: 1, UpdatedAt: 1}
	companion := Endpoint{EndpointID: companionID, CredentialHash: strings.Repeat("b", 43), Role: protocol.Companion, ConnectionID: "companion", CreatedAt: 1, UpdatedAt: 1}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"LINK#" + linkID:           storageItem(t, "link", linkID, link),
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, controller),
		"ENDPOINT#" + companionID:  storageItem(t, "endpoint", companionID, companion),
	}}
	store := NewDynamoStore("table", db)
	if _, err := store.OpenSession(context.Background(), linkID, controllerID, "controller", sessionID, 100); err != nil {
		t.Fatal(err)
	}
	transaction := db.transactions[0].TransactItems
	if len(transaction) != 4 {
		t.Fatalf("transaction actions = %d", len(transaction))
	}
	targets := map[string]bool{}
	for _, operation := range transaction {
		if operation.Put != nil {
			targets[storagePK(operation.Put.Item)] = true
		}
		if operation.Update != nil {
			targets[storagePK(operation.Update.Key)] = true
		}
	}
	for _, target := range []string{"SESSION#" + sessionID, "LINK#" + linkID, "ENDPOINT#" + controllerID, "ENDPOINT#" + companionID} {
		if !targets[target] {
			t.Fatalf("missing transaction target %s", target)
		}
	}
	for target := range targets {
		if strings.HasPrefix(target, "CONNECTION#") {
			t.Fatalf("unexpected connection lock %s", target)
		}
	}
}

func TestCloseSessionAtomicallyClearsRoutePointers(t *testing.T) {
	controllerID, companionID := storageUUID("000000000020"), storageUUID("000000000021")
	linkID, sessionID := storageUUID("000000000022"), storageUUID("000000000023")
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion",
		Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1000,
	}
	link := Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE", ActiveSessionID: sessionID, CreatedAt: 1}
	controller := Endpoint{EndpointID: controllerID, ConnectionID: "controller", ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1}
	companion := Endpoint{EndpointID: companionID, ConnectionID: "companion", ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"SESSION#" + sessionID:     storageItem(t, "session", sessionID, session),
		"LINK#" + linkID:           storageItem(t, "link", linkID, link),
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, controller),
		"ENDPOINT#" + companionID:  storageItem(t, "endpoint", companionID, companion),
	}}
	store := NewDynamoStore("table", db)
	result, err := store.CloseSession(context.Background(), sessionID, controllerID, "controller", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.ClosedNow || result.Session.ClosedAt != 100 {
		t.Fatalf("result = %#v", result)
	}
	if got := len(db.transactions[0].TransactItems); got != 4 {
		t.Fatalf("transaction actions = %d", got)
	}
	for _, operation := range db.transactions[0].TransactItems {
		if operation.Update != nil && storagePK(operation.Update.Key) == "ENDPOINT#"+controllerID &&
			!strings.Contains(*operation.Update.ConditionExpression, "connectionId = :connectionId") {
			t.Fatalf("close authority condition = %s", *operation.Update.ConditionExpression)
		}
	}
}

func TestSessionReadRepairsExpiredRoute(t *testing.T) {
	controllerID, companionID := storageUUID("000000000025"), storageUUID("000000000026")
	linkID, sessionID := storageUUID("000000000027"), storageUUID("000000000028")
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion",
		Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 100,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"SESSION#" + sessionID: storageItem(t, "session", sessionID, session),
		"LINK#" + linkID: storageItem(t, "link", linkID, Link{
			LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
			Status: "ACTIVE", ActiveSessionID: sessionID, CreatedAt: 1,
		}),
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, Endpoint{
			EndpointID: controllerID, ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1,
		}),
		"ENDPOINT#" + companionID: storageItem(t, "endpoint", companionID, Endpoint{
			EndpointID: companionID, ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1,
		}),
	}}
	store := NewDynamoStore("table", db)
	_, err := store.Session(context.Background(), sessionID, 100)
	serviceErr, ok := err.(*ServiceError)
	if !ok || serviceErr.Code != protocol.SessionNotFound {
		t.Fatalf("error = %#v", err)
	}
	if len(db.transactions) != 1 || len(db.transactions[0].TransactItems) != 4 {
		t.Fatalf("transactions = %#v", db.transactions)
	}
	targets := map[string]bool{}
	for _, operation := range db.transactions[0].TransactItems {
		if operation.Update != nil {
			targets[storagePK(operation.Update.Key)] = true
		}
	}
	for _, target := range []string{"SESSION#" + sessionID, "LINK#" + linkID, "ENDPOINT#" + controllerID, "ENDPOINT#" + companionID} {
		if !targets[target] {
			t.Fatalf("missing repair target %s", target)
		}
	}
}

func TestStaleDisconnectDeletesOnlyItsConnection(t *testing.T) {
	endpointID := storageUUID("000000000030")
	connection := Connection{ConnectionID: "old", AuthMode: "endpoint", EndpointID: endpointID, SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1000}
	endpoint := Endpoint{EndpointID: endpointID, ConnectionID: "new", CreatedAt: 1, UpdatedAt: 2}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"CONNECTION#old":         storageItem(t, "connection", "old", connection),
		"ENDPOINT#" + endpointID: storageItem(t, "endpoint", endpointID, endpoint),
	}}
	store := NewDynamoStore("table", db)
	result, err := store.Disconnect(context.Background(), "old", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Connection.ConnectionID != "old" || result.Session != nil {
		t.Fatalf("result = %#v", result)
	}
	transaction := db.transactions[0].TransactItems
	if len(transaction) != 1 || transaction[0].Delete == nil || storagePK(transaction[0].Delete.Key) != "CONNECTION#old" {
		t.Fatalf("transaction = %#v", transaction)
	}
}

func TestConnectReplacementDeletesObservedOldConnection(t *testing.T) {
	endpointID := storageUUID("000000000035")
	endpoint := Endpoint{
		EndpointID: endpointID, CredentialHash: "validated", Role: protocol.Controller,
		ConnectionID: "old", CreatedAt: 1, UpdatedAt: 1,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"ENDPOINT#" + endpointID: storageItem(t, "endpoint", endpointID, endpoint),
	}}
	store := NewDynamoStore("table", db)
	_, err := store.Connect(context.Background(), Connection{
		ConnectionID: "new", AuthMode: "endpoint", EndpointID: endpointID,
		SourceKey: "source", ConnectedAt: 100, ExpiresAt: 1000,
	}, "validated")
	if err != nil {
		t.Fatal(err)
	}
	transaction := db.transactions[0].TransactItems
	if len(transaction) != 3 || transaction[2].Delete == nil || storagePK(transaction[2].Delete.Key) != "CONNECTION#old" {
		t.Fatalf("transaction = %#v", transaction)
	}
	if condition := *transaction[1].Update.ConditionExpression; !strings.Contains(condition, "connectionId = :oldConnectionId") {
		t.Fatalf("condition = %s", condition)
	}
	if condition := *transaction[1].Update.ConditionExpression; !strings.Contains(condition, "credentialHash = :credentialHash") {
		t.Fatalf("credential condition = %s", condition)
	}
}

func TestConnectReplacementAtomicallyClosesOwnedSession(t *testing.T) {
	controllerID, companionID := storageUUID("000000000044"), storageUUID("000000000045")
	linkID, sessionID := storageUUID("000000000046"), storageUUID("000000000047")
	endpoint := Endpoint{
		EndpointID: controllerID, CredentialHash: "validated", Role: protocol.Controller,
		ConnectionID: "old", ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1,
	}
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "old", CompanionConnectionID: "companion",
		Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1_000,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, endpoint),
		"ENDPOINT#" + companionID: storageItem(t, "endpoint", companionID, Endpoint{
			EndpointID: companionID, ConnectionID: "companion", ActiveSessionID: sessionID,
		}),
		"LINK#" + linkID: storageItem(t, "link", linkID, Link{
			LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
			Status: "ACTIVE", ActiveSessionID: sessionID,
		}),
		"SESSION#" + sessionID: storageItem(t, "session", sessionID, session),
	}}
	result, err := NewDynamoStore("table", db).Connect(context.Background(), Connection{
		ConnectionID: "new", AuthMode: "endpoint", EndpointID: controllerID,
		SourceKey: "source", ConnectedAt: 100, ExpiresAt: 1_000,
	}, "validated")
	if err != nil || result == nil || !result.ClosedNow {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if len(db.transactions) != 1 || len(db.transactions[0].TransactItems) != 6 {
		t.Fatalf("transactions = %#v", db.transactions)
	}
	targets := map[string]int{}
	for _, operation := range db.transactions[0].TransactItems {
		switch {
		case operation.Put != nil:
			targets[storagePK(operation.Put.Item)]++
		case operation.Update != nil:
			targets[storagePK(operation.Update.Key)]++
			if storagePK(operation.Update.Key) == "ENDPOINT#"+controllerID {
				if !strings.Contains(*operation.Update.UpdateExpression, "REMOVE activeSessionId") ||
					!strings.Contains(*operation.Update.ConditionExpression, "connectionId = :oldConnectionId AND activeSessionId = :sessionId") {
					t.Fatalf("ownership update = %#v", operation.Update)
				}
			}
		case operation.Delete != nil:
			targets[storagePK(operation.Delete.Key)]++
		}
	}
	for _, target := range []string{
		"CONNECTION#new", "CONNECTION#old", "ENDPOINT#" + controllerID,
		"SESSION#" + sessionID, "LINK#" + linkID, "ENDPOINT#" + companionID,
	} {
		if targets[target] != 1 {
			t.Fatalf("target %s count = %d in %v", target, targets[target], targets)
		}
	}
}

func TestPairingDisconnectAtomicallyCancelsOwnedPair(t *testing.T) {
	pairID := storageUUID("000000000048")
	connection := Connection{
		ConnectionID: "pairing", AuthMode: "pairing", PairingID: pairID,
		SourceKey: "source", ConnectedAt: 1, ExpiresAt: 1_000,
	}
	pair := Pair{
		PairID: pairID, Locator: "123456", Status: "READY",
		SideA:     PairSide{ConnectionID: connection.ConnectionID, SideID: storageUUID("000000000049")},
		ExpiresAt: 1_000,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"CONNECTION#" + connection.ConnectionID: storageItem(t, "connection", connection.ConnectionID, connection),
		"PAIR#" + pairID:                        storageItem(t, "pair", pairID, pair),
	}}
	result, err := NewDynamoStore("table", db).Disconnect(context.Background(), connection.ConnectionID, 100)
	if err != nil || result == nil || result.Connection.PairingID != pairID {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if len(db.transactions) != 1 || len(db.transactions[0].TransactItems) != 2 {
		t.Fatalf("transactions = %#v", db.transactions)
	}
	transaction := db.transactions[0].TransactItems
	if transaction[0].Delete == nil || storagePK(transaction[0].Delete.Key) != "CONNECTION#"+connection.ConnectionID {
		t.Fatalf("connection delete = %#v", transaction[0])
	}
	if transaction[1].Update == nil || storagePK(transaction[1].Update.Key) != "PAIR#"+pairID ||
		!strings.Contains(*transaction[1].Update.ConditionExpression, "#status <> :active") ||
		!strings.Contains(*transaction[1].Update.ConditionExpression, "sideA.connectionId = :connectionId") {
		t.Fatalf("pair cancellation = %#v", transaction[1])
	}
}

func TestOppositeCommitActivatesWithoutVersionField(t *testing.T) {
	pairID := storageUUID("000000000036")
	linkID := storageUUID("000000000037")
	aID, bID := storageUUID("000000000038"), storageUUID("000000000039")
	a := PairCommit{
		ConnectionID: "a", SideID: storageUUID("000000000050"), LinkID: linkID,
		Self: PairEndpointCommit{EndpointID: aID, Role: protocol.Controller, CredentialHash: "a"},
		Peer: PairIdentity{EndpointID: bID, Role: protocol.Companion},
	}
	b := PairCommit{
		ConnectionID: "b", SideID: storageUUID("000000000051"), LinkID: linkID,
		Self: PairEndpointCommit{EndpointID: bID, Role: protocol.Companion, CredentialHash: "b"},
		Peer: PairIdentity{EndpointID: aID, Role: protocol.Controller},
	}
	pair := Pair{
		PairID: pairID, Locator: "123456", Status: "HALF_COMMITTED",
		SideA:   PairSide{ConnectionID: "a", SideID: a.SideID},
		SideB:   &PairSide{ConnectionID: "b", SideID: b.SideID},
		CommitA: &a, ExpiresAt: 1_000,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"PAIR#" + pairID: storageItem(t, "pair", pairID, pair),
	}}
	result, err := NewDynamoStore("table", db).CommitPair(context.Background(), pairID, b, 100)
	if err != nil || result.Link == nil || result.Pair.Status != "ACTIVE" {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if len(db.transactions) != 1 || len(db.transactions[0].TransactItems) != 4 {
		t.Fatalf("transactions = %#v", db.transactions)
	}
	update := db.transactions[0].TransactItems[0].Update
	if update == nil || strings.Contains(*update.UpdateExpression, "version") || strings.Contains(*update.ConditionExpression, "version") {
		t.Fatalf("pair activation update = %#v", update)
	}
	for _, clause := range []string{"#status = :half", "attribute_not_exists(commitB)"} {
		if !strings.Contains(*update.ConditionExpression, clause) {
			t.Fatalf("activation condition missing %q: %s", clause, *update.ConditionExpression)
		}
	}
}

func TestPairActivationUsesGlobalDailyCircuitBreaker(t *testing.T) {
	pairID := storageUUID("000000000060")
	linkID := storageUUID("000000000061")
	aID, bID := storageUUID("000000000062"), storageUUID("000000000063")
	a := PairCommit{
		ConnectionID: "a", SideID: storageUUID("000000000064"), LinkID: linkID,
		Self: PairEndpointCommit{EndpointID: aID, Role: protocol.Controller, CredentialHash: "a"},
		Peer: PairIdentity{EndpointID: bID, Role: protocol.Companion},
	}
	b := PairCommit{
		ConnectionID: "b", SideID: storageUUID("000000000065"), LinkID: linkID,
		Self: PairEndpointCommit{EndpointID: bID, Role: protocol.Companion, CredentialHash: "b"},
		Peer: PairIdentity{EndpointID: aID, Role: protocol.Controller},
	}
	pair := Pair{
		PairID: pairID, Locator: "123456", Status: "HALF_COMMITTED",
		SideA: PairSide{ConnectionID: "a", SideID: a.SideID},
		SideB: &PairSide{ConnectionID: "b", SideID: b.SideID}, CommitA: &a, ExpiresAt: 200_000,
	}
	db := &storageDynamo{
		items: map[string]map[string]types.AttributeValue{
			"PAIR#" + pairID: storageItem(t, "pair", pairID, pair),
		},
		updateItem: func(input *dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			if storagePK(input.Key) != "RATE#global#pair.activate#1" ||
				input.ExpressionAttributeValues[":limit"].(*types.AttributeValueMemberN).Value != "10000" ||
				input.ExpressionAttributeValues[":expiresAt"].(*types.AttributeValueMemberN).Value != "259200" {
				t.Fatalf("daily rate update = %#v", input)
			}
			return nil, &types.ConditionalCheckFailedException{}
		},
	}
	_, err := NewDynamoStore("table", db).CommitPair(context.Background(), pairID, b, 90_000)
	var service *ServiceError
	if !errors.As(err, &service) || service.Code != protocol.RateLimited || service.RetryAfterMS == nil || *service.RetryAfterMS != 3_600_000 {
		t.Fatalf("error = %#v", err)
	}
	if len(db.updates) != 1 || len(db.transactions) != 0 {
		t.Fatalf("updates = %d, transactions = %d", len(db.updates), len(db.transactions))
	}
}

func TestPairCancellationLosesToConcurrentActivation(t *testing.T) {
	pairID := storageUUID("000000000052")
	half := Pair{
		PairID: pairID, Locator: "123456", Status: "HALF_COMMITTED",
		SideA: PairSide{ConnectionID: "a", SideID: storageUUID("000000000053")}, ExpiresAt: 1_000,
	}
	active := half
	active.Status = "ACTIVE"
	reads := 0
	db := &storageDynamo{
		getItem: func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			reads++
			value := half
			if reads > 1 {
				value = active
			}
			return &dynamodb.GetItemOutput{Item: storageItem(t, "pair", pairID, value)}, nil
		},
		updateItem: func(*dynamodb.UpdateItemInput) (*dynamodb.UpdateItemOutput, error) {
			return nil, &types.ConditionalCheckFailedException{}
		},
	}
	_, err := NewDynamoStore("table", db).CancelPair(context.Background(), pairID, "a", 100)
	var service *ServiceError
	if !errors.As(err, &service) || service.Code != protocol.Conflict || service.Retryable {
		t.Fatalf("error = %#v", err)
	}
}

func TestLinkRevokeAtomicallyClosesActiveSession(t *testing.T) {
	controllerID, companionID := storageUUID("000000000054"), storageUUID("000000000055")
	linkID, sessionID := storageUUID("000000000056"), storageUUID("000000000057")
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion",
		Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1_000,
	}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"LINK#" + linkID: storageItem(t, "link", linkID, Link{
			LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
			Status: "ACTIVE", ActiveSessionID: sessionID,
		}),
		"SESSION#" + sessionID: storageItem(t, "session", sessionID, session),
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, Endpoint{
			EndpointID: controllerID, ConnectionID: "controller", ActiveSessionID: sessionID,
		}),
		"ENDPOINT#" + companionID: storageItem(t, "endpoint", companionID, Endpoint{
			EndpointID: companionID, ConnectionID: "companion", ActiveSessionID: sessionID,
		}),
	}}
	result, err := NewDynamoStore("table", db).RevokeLink(context.Background(), linkID, controllerID, "controller", 100)
	if err != nil || result.Link.Status != "REVOKED" || result.Session == nil || !result.Session.ClosedNow {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
	if len(db.transactions) != 1 || len(db.transactions[0].TransactItems) != 4 {
		t.Fatalf("transactions = %#v", db.transactions)
	}
	want := map[string]bool{
		"LINK#" + linkID: true, "SESSION#" + sessionID: true,
		"ENDPOINT#" + controllerID: true, "ENDPOINT#" + companionID: true,
	}
	for _, operation := range db.transactions[0].TransactItems {
		if operation.Update == nil || !want[storagePK(operation.Update.Key)] {
			t.Fatalf("unexpected operation %#v", operation)
		}
		if storagePK(operation.Update.Key) == "ENDPOINT#"+controllerID &&
			!strings.Contains(*operation.Update.ConditionExpression, "connectionId = :connectionId") {
			t.Fatalf("revoke authority condition = %s", *operation.Update.ConditionExpression)
		}
		delete(want, storagePK(operation.Update.Key))
	}
	if len(want) != 0 {
		t.Fatalf("missing targets = %v", want)
	}
}

func TestLinkRevokeWithoutSessionStillFencesConnection(t *testing.T) {
	controllerID, companionID := storageUUID("000000000067"), storageUUID("000000000068")
	linkID := storageUUID("000000000069")
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, Endpoint{
			EndpointID: controllerID, ConnectionID: "controller",
		}),
		"LINK#" + linkID: storageItem(t, "link", linkID, Link{
			LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE",
		}),
	}}
	if _, err := NewDynamoStore("table", db).RevokeLink(context.Background(), linkID, controllerID, "controller", 100); err != nil {
		t.Fatal(err)
	}
	transaction := db.transactions[0].TransactItems
	if len(transaction) != 2 || transaction[1].ConditionCheck == nil ||
		storagePK(transaction[1].ConditionCheck.Key) != "ENDPOINT#"+controllerID ||
		!strings.Contains(*transaction[1].ConditionCheck.ConditionExpression, "connectionId = :connectionId") {
		t.Fatalf("transaction = %#v", transaction)
	}
}

func TestEndpointRevokeClosesOneActiveRouteInConstantWork(t *testing.T) {
	controllerID, companionID := storageUUID("000000000040"), storageUUID("000000000041")
	linkID, sessionID := storageUUID("000000000042"), storageUUID("000000000043")
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controllerID, CompanionID: companionID,
		ControllerConnectionID: "controller", CompanionConnectionID: "companion",
		Status: "ACTIVE", CreatedAt: 1, ExpiresAt: 1000,
	}
	link := Link{LinkID: linkID, ControllerID: controllerID, CompanionID: companionID, Status: "ACTIVE", ActiveSessionID: sessionID, CreatedAt: 1}
	controller := Endpoint{EndpointID: controllerID, ConnectionID: "controller", ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1}
	companion := Endpoint{EndpointID: companionID, ConnectionID: "companion", ActiveSessionID: sessionID, CreatedAt: 1, UpdatedAt: 1}
	db := &storageDynamo{items: map[string]map[string]types.AttributeValue{
		"SESSION#" + sessionID:     storageItem(t, "session", sessionID, session),
		"LINK#" + linkID:           storageItem(t, "link", linkID, link),
		"ENDPOINT#" + controllerID: storageItem(t, "endpoint", controllerID, controller),
		"ENDPOINT#" + companionID:  storageItem(t, "endpoint", companionID, companion),
	}}
	store := NewDynamoStore("table", db)
	result, err := store.RevokeEndpoint(context.Background(), controllerID, "controller", 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Session == nil || !result.Session.ClosedNow || result.Endpoint.RevokedAt != 100 {
		t.Fatalf("result = %#v", result)
	}
	if got := len(db.transactions[0].TransactItems); got != 5 {
		t.Fatalf("transaction actions = %d", got)
	}
	transaction := db.transactions[0].TransactItems
	if !strings.Contains(*transaction[0].Update.ConditionExpression, "connectionId = :connectionId") ||
		transaction[1].Delete == nil || storagePK(transaction[1].Delete.Key) != "CONNECTION#controller" {
		t.Fatalf("endpoint revoke fence = %#v", transaction[:2])
	}
}

func TestEndpointRevokeLosesToConnectionReplacement(t *testing.T) {
	endpointID := storageUUID("000000000066")
	replaced := false
	db := &storageDynamo{
		getItem: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
			connectionID := "old"
			if replaced {
				connectionID = "new"
			}
			return &dynamodb.GetItemOutput{Item: storageItem(t, "endpoint", endpointID, Endpoint{
				EndpointID: endpointID, ConnectionID: connectionID,
			})}, nil
		},
		transact: func(*dynamodb.TransactWriteItemsInput) (*dynamodb.TransactWriteItemsOutput, error) {
			replaced = true
			return nil, &types.ConditionalCheckFailedException{}
		},
	}
	_, err := NewDynamoStore("table", db).RevokeEndpoint(context.Background(), endpointID, "old", 100)
	var service *ServiceError
	if !errors.As(err, &service) || service.Code != protocol.Unauthenticated || len(db.transactions) != 1 {
		t.Fatalf("transactions = %d, error = %#v", len(db.transactions), err)
	}
}
