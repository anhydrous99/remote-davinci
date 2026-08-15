package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const meta = "META"

type Store interface {
	GetEndpoint(context.Context, string) (*Endpoint, error)
	Connect(context.Context, Connection, string) error
	Disconnect(context.Context, string) (*Connection, error)
	Connection(context.Context, string, int64) (Connection, error)
	RateLimit(context.Context, string, string, int64, int64) error
	CreatePair(context.Context, Pair) error
	PairByID(context.Context, string, int64) (Pair, error)
	PairByLocator(context.Context, string, int64) (Pair, error)
	JoinPair(context.Context, string, PairSide, int64) (Pair, error)
	CommitPair(context.Context, string, PairCommit, int64) (CommitPairResult, error)
	CancelPair(context.Context, string, string, int64) (*Pair, error)
	Link(context.Context, string) (*Link, error)
	RevokeLink(context.Context, string, string, int64) (Link, error)
	RotateEndpoint(context.Context, string, string, int64) error
	RevokeEndpoint(context.Context, string, int64) (RevokeEndpointResult, error)
	OpenSession(context.Context, string, string, string, string, int64) (Session, error)
	Session(context.Context, string, int64) (Session, error)
	CloseSession(context.Context, string, string, int64) (*CloseSessionResult, error)
}

type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	DeleteItem(context.Context, *dynamodb.DeleteItemInput, ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
	Query(context.Context, *dynamodb.QueryInput, ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

type DynamoStore struct {
	tableName string
	db        DynamoAPI
}

func NewDynamoStore(tableName string, db DynamoAPI) *DynamoStore {
	return &DynamoStore{tableName: tableName, db: db}
}

func key(prefix, id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: strings.ToUpper(prefix) + "#" + id},
		"sk": &types.AttributeValueMemberS{Value: meta},
	}
}

func marshalItem(kind, id string, value any) (map[string]types.AttributeValue, error) {
	item, err := attributevalue.MarshalMap(value)
	if err != nil {
		return nil, err
	}
	item["pk"] = &types.AttributeValueMemberS{Value: strings.ToUpper(kind) + "#" + id}
	item["sk"] = &types.AttributeValueMemberS{Value: meta}
	item["kind"] = &types.AttributeValueMemberS{Value: kind}
	return item, nil
}

func values(input map[string]any) (map[string]types.AttributeValue, error) {
	return attributevalue.MarshalMap(input)
}

func (s *DynamoStore) get(ctx context.Context, kind, id string, target any) (bool, error) {
	result, err := s.db.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName), Key: key(kind, id), ConsistentRead: aws.Bool(true),
	})
	if err != nil || len(result.Item) == 0 {
		return false, err
	}
	if err := attributevalue.UnmarshalMap(result.Item, target); err != nil {
		return false, err
	}
	return true, nil
}

func conditionalFailure(err error) bool {
	var apiError interface{ ErrorCode() string }
	if !errors.As(err, &apiError) {
		return false
	}
	return apiError.ErrorCode() == "ConditionalCheckFailedException" || apiError.ErrorCode() == "TransactionCanceledException"
}

func (s *DynamoStore) GetEndpoint(ctx context.Context, endpointID string) (*Endpoint, error) {
	var endpoint Endpoint
	found, err := s.get(ctx, "ENDPOINT", endpointID, &endpoint)
	if err != nil || !found {
		return nil, err
	}
	return &endpoint, nil
}

func (s *DynamoStore) Connect(ctx context.Context, connection Connection, credentialHash string) error {
	if connection.AuthMode == "endpoint" && (connection.EndpointID == "" || credentialHash == "") ||
		connection.AuthMode == "pairing" && connection.EndpointID != "" {
		return serviceError(protocol.Unauthenticated)
	}
	item, err := marshalItem("connection", connection.ConnectionID, connection)
	if err != nil {
		return err
	}
	operations := []types.TransactWriteItem{{Put: &types.Put{
		TableName: aws.String(s.tableName), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
	}}}
	if connection.EndpointID != "" {
		expressionValues, err := values(map[string]any{
			":connectionId": connection.ConnectionID, ":now": connection.ConnectedAt, ":credentialHash": credentialHash,
		})
		if err != nil {
			return err
		}
		operations = append(operations, types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", connection.EndpointID),
			UpdateExpression:          aws.String("SET connectionId = :connectionId, updatedAt = :now"),
			ConditionExpression:       aws.String("attribute_exists(pk) AND attribute_not_exists(revokedAt) AND credentialHash = :credentialHash"),
			ExpressionAttributeValues: expressionValues,
		}})
	}
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
	if conditionalFailure(err) {
		return serviceError(protocol.Unauthenticated)
	}
	return err
}

func (s *DynamoStore) Disconnect(ctx context.Context, connectionID string) (*Connection, error) {
	var connection Connection
	found, err := s.get(ctx, "CONNECTION", connectionID, &connection)
	if err != nil || !found {
		return nil, err
	}
	_, _ = s.db.DeleteItem(ctx, &dynamodb.DeleteItemInput{TableName: aws.String(s.tableName), Key: key("CONNECTION", connectionID)})
	if connection.EndpointID != "" {
		expressionValues, marshalErr := values(map[string]any{":connectionId": connectionID})
		if marshalErr == nil {
			_, _ = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
				TableName: aws.String(s.tableName), Key: key("ENDPOINT", connection.EndpointID),
				UpdateExpression: aws.String("REMOVE connectionId"), ConditionExpression: aws.String("connectionId = :connectionId"),
				ExpressionAttributeValues: expressionValues,
			})
		}
	}
	return &connection, nil
}

func (s *DynamoStore) Connection(ctx context.Context, connectionID string, now int64) (Connection, error) {
	var connection Connection
	found, err := s.get(ctx, "CONNECTION", connectionID, &connection)
	if err != nil {
		return Connection{}, err
	}
	if !found || isExpired(connection, now) {
		return Connection{}, serviceError(protocol.Unauthenticated)
	}
	if connection.EndpointID != "" {
		endpoint, err := s.GetEndpoint(ctx, connection.EndpointID)
		if err != nil {
			return Connection{}, err
		}
		if endpoint == nil || endpoint.RevokedAt != 0 || endpoint.ConnectionID != connectionID {
			return Connection{}, serviceError(protocol.Unauthenticated)
		}
	}
	return connection, nil
}

func (s *DynamoStore) RateLimit(ctx context.Context, sourceKey, action string, limit, now int64) error {
	minute := now / 60
	expressionValues, err := values(map[string]any{
		":expiresAt": (minute + 2) * 60, ":one": int64(1), ":limit": limit,
	})
	if err != nil {
		return err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("RATE", fmt.Sprintf("%s#%s#%d", sourceKey, action, minute)),
		UpdateExpression:         aws.String("SET expiresAt = :expiresAt ADD #count :one"),
		ConditionExpression:      aws.String("attribute_not_exists(#count) OR #count < :limit"),
		ExpressionAttributeNames: map[string]string{"#count": "count"}, ExpressionAttributeValues: expressionValues,
	})
	if conditionalFailure(err) {
		retryAfter := int64(60_000)
		return &ServiceError{Code: protocol.RateLimited, Retryable: true, RetryAfterMS: &retryAfter}
	}
	return err
}

type pairPointer struct {
	PairID    string `dynamodbav:"pairId"`
	Locator   string `dynamodbav:"locator"`
	ExpiresAt int64  `dynamodbav:"expiresAt"`
}

func (pointer pairPointer) Expiry() int64 { return pointer.ExpiresAt }

func (s *DynamoStore) CreatePair(ctx context.Context, pair Pair) error {
	pairItem, err := marshalItem("pair", pair.Locator, pair)
	if err != nil {
		return err
	}
	pointerItem, err := marshalItem("pairid", pair.PairID, pairPointer{PairID: pair.PairID, Locator: pair.Locator, ExpiresAt: pair.ExpiresAt})
	if err != nil {
		return err
	}
	expressionValues, err := values(map[string]any{":pairId": pair.PairID, ":pairing": "pairing"})
	if err != nil {
		return err
	}
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.tableName), Item: pairItem, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		{Put: &types.Put{TableName: aws.String(s.tableName), Item: pointerItem, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("CONNECTION", pair.SideA.ConnectionID),
			UpdateExpression:          aws.String("SET pairingId = :pairId"),
			ConditionExpression:       aws.String("authMode = :pairing AND attribute_not_exists(pairingId)"),
			ExpressionAttributeValues: expressionValues,
		}},
	}})
	if conditionalFailure(err) {
		return retryableError(protocol.Conflict)
	}
	return err
}

func (s *DynamoStore) PairByLocator(ctx context.Context, locator string, now int64) (Pair, error) {
	var pair Pair
	found, err := s.get(ctx, "PAIR", locator, &pair)
	if err != nil {
		return Pair{}, err
	}
	if !found || isExpired(pair, now) {
		return Pair{}, serviceError(protocol.PairExpired)
	}
	return pair, nil
}

func (s *DynamoStore) PairByID(ctx context.Context, pairID string, now int64) (Pair, error) {
	var pointer pairPointer
	found, err := s.get(ctx, "PAIRID", pairID, &pointer)
	if err != nil {
		return Pair{}, err
	}
	if !found || isExpired(pointer, now) {
		return Pair{}, serviceError(protocol.PairExpired)
	}
	pair, err := s.PairByLocator(ctx, pointer.Locator, now)
	if err != nil {
		return Pair{}, err
	}
	if pair.PairID != pairID {
		return Pair{}, serviceError(protocol.PairUnavailable)
	}
	return pair, nil
}

func (s *DynamoStore) JoinPair(ctx context.Context, locator string, side PairSide, now int64) (Pair, error) {
	pair, err := s.PairByLocator(ctx, locator, now)
	if err != nil {
		return Pair{}, err
	}
	if pair.Status != "OPEN" || pair.SideB != nil {
		return Pair{}, serviceError(protocol.PairFull)
	}
	updateValues, err := values(map[string]any{
		":side": side, ":ready": "READY", ":open": "OPEN", ":version": pair.Version,
		":nextVersion": pair.Version + 1, ":now": now,
	})
	if err != nil {
		return Pair{}, err
	}
	connectionValues, err := values(map[string]any{":pairId": pair.PairID, ":pairing": "pairing"})
	if err != nil {
		return Pair{}, err
	}
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("PAIR", locator),
			UpdateExpression:         aws.String("SET sideB = :side, #status = :ready, version = :nextVersion"),
			ConditionExpression:      aws.String("#status = :open AND version = :version AND expiresAt > :now AND attribute_not_exists(sideB)"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: updateValues,
		}},
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("CONNECTION", side.ConnectionID),
			UpdateExpression:          aws.String("SET pairingId = :pairId"),
			ConditionExpression:       aws.String("authMode = :pairing AND attribute_not_exists(pairingId)"),
			ExpressionAttributeValues: connectionValues,
		}},
	}})
	if conditionalFailure(err) {
		return Pair{}, serviceError(protocol.PairFull)
	}
	if err != nil {
		return Pair{}, err
	}
	pair.SideB, pair.Status, pair.Version = &side, "READY", pair.Version+1
	return pair, nil
}

func (s *DynamoStore) endpointWrite(ctx context.Context, endpoint Endpoint) (types.TransactWriteItem, error) {
	existing, err := s.GetEndpoint(ctx, endpoint.EndpointID)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	if existing == nil {
		item, err := marshalItem("endpoint", endpoint.EndpointID, endpoint)
		if err != nil {
			return types.TransactWriteItem{}, err
		}
		return types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(s.tableName), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
		}}, nil
	}
	if existing.RevokedAt != 0 || existing.CredentialHash != endpoint.CredentialHash || existing.Role != endpoint.Role {
		return types.TransactWriteItem{}, serviceError(protocol.Conflict)
	}
	expressionValues, err := values(map[string]any{":credentialHash": endpoint.CredentialHash, ":role": endpoint.Role})
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpoint.EndpointID),
		ConditionExpression:      aws.String("credentialHash = :credentialHash AND #role = :role AND attribute_not_exists(revokedAt)"),
		ExpressionAttributeNames: map[string]string{"#role": "role"}, ExpressionAttributeValues: expressionValues,
	}}, nil
}

func (s *DynamoStore) CommitPair(ctx context.Context, pairID string, commit PairCommit, now int64) (CommitPairResult, error) {
	pair, err := s.PairByID(ctx, pairID, now)
	if err != nil {
		return CommitPairResult{}, err
	}
	slot := ""
	if pair.SideA.SideID == commit.SideID && pair.SideA.ConnectionID == commit.ConnectionID {
		slot = "A"
	} else if pair.SideB != nil && pair.SideB.SideID == commit.SideID && pair.SideB.ConnectionID == commit.ConnectionID {
		slot = "B"
	}
	if slot == "" {
		return CommitPairResult{}, serviceError(protocol.Forbidden)
	}
	own, other := pair.CommitA, pair.CommitB
	ownField := "commitA"
	if slot == "B" {
		own, other, ownField = pair.CommitB, pair.CommitA, "commitB"
	}
	if pair.Status == "ACTIVE" && own != nil && SameCommit(*own, commit) {
		link, err := s.Link(ctx, commit.LinkID)
		return CommitPairResult{Pair: pair, Link: link}, err
	}
	if own != nil {
		if !SameCommit(*own, commit) {
			return CommitPairResult{}, serviceError(protocol.Conflict)
		}
		return CommitPairResult{Pair: pair}, nil
	}
	if pair.Status != "READY" && pair.Status != "HALF_COMMITTED" {
		return CommitPairResult{}, serviceError(protocol.PairUnavailable)
	}
	if other == nil {
		expressionValues, err := values(map[string]any{
			":commit": commit, ":half": "HALF_COMMITTED", ":ready": "READY",
			":version": pair.Version, ":nextVersion": pair.Version + 1,
		})
		if err != nil {
			return CommitPairResult{}, err
		}
		_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(s.tableName), Key: key("PAIR", pair.Locator),
			UpdateExpression:         aws.String("SET " + ownField + " = :commit, #status = :half, version = :nextVersion"),
			ConditionExpression:      aws.String("version = :version AND (#status = :ready OR #status = :half) AND attribute_not_exists(" + ownField + ")"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		})
		if conditionalFailure(err) {
			return CommitPairResult{}, retryableError(protocol.Conflict)
		}
		if err != nil {
			return CommitPairResult{}, err
		}
		if slot == "A" {
			pair.CommitA = &commit
		} else {
			pair.CommitB = &commit
		}
		pair.Status, pair.Version = "HALF_COMMITTED", pair.Version+1
		return CommitPairResult{Pair: pair}, nil
	}
	first, second := *other, commit
	if slot == "A" {
		first, second = commit, *other
	}
	link, err := LinkFromCommits(first, second, now)
	if err != nil {
		return CommitPairResult{}, err
	}
	endpoints := []Endpoint{
		{EndpointID: first.Self.EndpointID, CredentialHash: first.Self.CredentialHash, Role: first.Self.Role, CreatedAt: now, UpdatedAt: now},
		{EndpointID: second.Self.EndpointID, CredentialHash: second.Self.CredentialHash, Role: second.Self.Role, CreatedAt: now, UpdatedAt: now},
	}
	endpointWrites := make([]types.TransactWriteItem, 0, 2)
	for _, endpoint := range endpoints {
		write, err := s.endpointWrite(ctx, endpoint)
		if err != nil {
			return CommitPairResult{}, err
		}
		endpointWrites = append(endpointWrites, write)
	}
	expressionValues, err := values(map[string]any{
		":commit": commit, ":active": "ACTIVE", ":half": "HALF_COMMITTED",
		":version": pair.Version, ":nextVersion": pair.Version + 1,
	})
	if err != nil {
		return CommitPairResult{}, err
	}
	linkItem, err := marshalItem("link", link.LinkID, link)
	if err != nil {
		return CommitPairResult{}, err
	}
	operations := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("PAIR", pair.Locator),
			UpdateExpression:         aws.String("SET " + ownField + " = :commit, #status = :active, version = :nextVersion"),
			ConditionExpression:      aws.String("version = :version AND #status = :half AND attribute_not_exists(" + ownField + ")"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		}},
		{Put: &types.Put{TableName: aws.String(s.tableName), Item: linkItem, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
	}
	for _, endpointID := range []string{link.ControllerID, link.CompanionID} {
		peerID := link.ControllerID
		if endpointID == link.ControllerID {
			peerID = link.CompanionID
		}
		memberItem, err := attributevalue.MarshalMap(map[string]any{
			"pk": "ENDPOINT#" + endpointID, "sk": "LINK#" + link.LinkID, "kind": "endpoint-link",
			"endpointId": endpointID, "linkId": link.LinkID, "peerEndpointId": peerID,
		})
		if err != nil {
			return CommitPairResult{}, err
		}
		operations = append(operations, types.TransactWriteItem{Put: &types.Put{
			TableName: aws.String(s.tableName), Item: memberItem, ConditionExpression: aws.String("attribute_not_exists(pk)"),
		}})
	}
	operations = append(operations, endpointWrites...)
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
	if conditionalFailure(err) {
		return CommitPairResult{}, retryableError(protocol.Conflict)
	}
	if err != nil {
		return CommitPairResult{}, err
	}
	if slot == "A" {
		pair.CommitA = &commit
	} else {
		pair.CommitB = &commit
	}
	pair.Status, pair.Version = "ACTIVE", pair.Version+1
	return CommitPairResult{Pair: pair, Link: &link}, nil
}

func (s *DynamoStore) CancelPair(ctx context.Context, pairID, connectionID string, now int64) (*Pair, error) {
	pair, err := s.PairByID(ctx, pairID, now)
	if err != nil {
		var service *ServiceError
		if errors.As(err, &service) && service.Code == protocol.PairExpired {
			return nil, nil
		}
		return nil, err
	}
	if pair.SideA.ConnectionID != connectionID && (pair.SideB == nil || pair.SideB.ConnectionID != connectionID) {
		return nil, serviceError(protocol.Forbidden)
	}
	if pair.Status == "ACTIVE" {
		return nil, serviceError(protocol.Conflict)
	}
	if pair.Status == "CLOSED" {
		return &pair, nil
	}
	expressionValues, err := values(map[string]any{
		":closed": "CLOSED", ":active": "ACTIVE", ":version": pair.Version, ":nextVersion": pair.Version + 1,
	})
	if err != nil {
		return nil, err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("PAIR", pair.Locator),
		UpdateExpression:         aws.String("SET #status = :closed, version = :nextVersion"),
		ConditionExpression:      aws.String("version = :version AND #status <> :active"),
		ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
	})
	if conditionalFailure(err) {
		current, readErr := s.PairByID(ctx, pairID, now)
		if readErr == nil && current.Status == "CLOSED" {
			return &current, nil
		}
		return nil, serviceError(protocol.Conflict)
	}
	if err != nil {
		return nil, err
	}
	pair.Status, pair.Version = "CLOSED", pair.Version+1
	return &pair, nil
}

func (s *DynamoStore) Link(ctx context.Context, linkID string) (*Link, error) {
	var link Link
	found, err := s.get(ctx, "LINK", linkID, &link)
	if err != nil || !found {
		return nil, err
	}
	return &link, nil
}

func (s *DynamoStore) RevokeLink(ctx context.Context, linkID, endpointID string, now int64) (Link, error) {
	link, err := s.Link(ctx, linkID)
	if err != nil {
		return Link{}, err
	}
	if link == nil || link.ControllerID != endpointID && link.CompanionID != endpointID {
		return Link{}, serviceError(protocol.Forbidden)
	}
	if link.Status == "REVOKED" {
		return *link, nil
	}
	expressionValues, err := values(map[string]any{":revoked": "REVOKED", ":active": "ACTIVE", ":now": now})
	if err != nil {
		return Link{}, err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("LINK", linkID),
		UpdateExpression:         aws.String("SET #status = :revoked, revokedAt = :now"),
		ConditionExpression:      aws.String("#status = :active"),
		ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
	})
	if err != nil && !conditionalFailure(err) {
		return Link{}, err
	}
	link.Status, link.RevokedAt = "REVOKED", now
	return *link, nil
}

func (s *DynamoStore) RotateEndpoint(ctx context.Context, endpointID, credentialHash string, now int64) error {
	expressionValues, err := values(map[string]any{":credentialHash": credentialHash, ":now": now})
	if err != nil {
		return err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
		UpdateExpression:          aws.String("SET credentialHash = :credentialHash, updatedAt = :now"),
		ConditionExpression:       aws.String("attribute_exists(pk) AND attribute_not_exists(revokedAt)"),
		ExpressionAttributeValues: expressionValues,
	})
	if conditionalFailure(err) {
		return serviceError(protocol.Unauthenticated)
	}
	return err
}

func (s *DynamoStore) RevokeEndpoint(ctx context.Context, endpointID string, now int64) (RevokeEndpointResult, error) {
	endpoint, err := s.GetEndpoint(ctx, endpointID)
	if err != nil {
		return RevokeEndpointResult{}, err
	}
	if endpoint == nil {
		return RevokeEndpointResult{}, serviceError(protocol.Unauthenticated)
	}
	if endpoint.RevokedAt == 0 {
		expressionValues, err := values(map[string]any{":now": now})
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
			UpdateExpression:    aws.String("SET revokedAt = :now, updatedAt = :now REMOVE connectionId, activeSessionId"),
			ConditionExpression: aws.String("attribute_not_exists(revokedAt)"), ExpressionAttributeValues: expressionValues,
		})
		if err != nil && !conditionalFailure(err) {
			return RevokeEndpointResult{}, err
		}
	}
	queryValues, err := values(map[string]any{":pk": "ENDPOINT#" + endpointID, ":prefix": "LINK#"})
	if err != nil {
		return RevokeEndpointResult{}, err
	}
	var linkIDs []string
	var startKey map[string]types.AttributeValue
	for {
		page, err := s.db.Query(ctx, &dynamodb.QueryInput{
			TableName:                 aws.String(s.tableName),
			KeyConditionExpression:    aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: queryValues, ProjectionExpression: aws.String("linkId"),
			ConsistentRead: aws.Bool(true), ExclusiveStartKey: startKey,
		})
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		for _, item := range page.Items {
			if value, ok := item["linkId"].(*types.AttributeValueMemberS); ok {
				linkIDs = append(linkIDs, value.Value)
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			break
		}
		startKey = page.LastEvaluatedKey
	}
	result := RevokeEndpointResult{}
	// ponytail: sequential cleanup fits device-scale link counts; use a workflow if fan-out approaches the Lambda timeout.
	for _, linkID := range linkIDs {
		link, err := s.Link(ctx, linkID)
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		if link == nil {
			continue
		}
		sessionID := link.ActiveSessionID
		revoked, err := s.RevokeLink(ctx, linkID, endpointID, now)
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		result.Links = append(result.Links, revoked)
		if sessionID != "" {
			closed, err := s.CloseSession(ctx, sessionID, "", now)
			if err != nil {
				return RevokeEndpointResult{}, err
			}
			if closed != nil && closed.ClosedNow {
				result.Sessions = append(result.Sessions, closed.Session)
			}
		}
	}
	endpoint.ConnectionID, endpoint.ActiveSessionID = "", ""
	if endpoint.RevokedAt == 0 {
		endpoint.RevokedAt = now
	}
	endpoint.UpdatedAt = now
	result.Endpoint = *endpoint
	return result, nil
}

func (s *DynamoStore) OpenSession(ctx context.Context, linkID, endpointID, connectionID, sessionID string, now int64) (Session, error) {
	link, err := s.Link(ctx, linkID)
	if err != nil {
		return Session{}, err
	}
	if link == nil || link.Status != "ACTIVE" || link.ControllerID != endpointID {
		return Session{}, serviceError(protocol.Forbidden)
	}
	if link.ActiveSessionID != "" {
		repaired, err := s.repairStaleSession(ctx, link.ActiveSessionID, *link, now)
		if err != nil {
			return Session{}, err
		}
		if repaired {
			link, err = s.Link(ctx, linkID)
			if err != nil {
				return Session{}, err
			}
			if link == nil || link.Status != "ACTIVE" || link.ActiveSessionID != "" {
				return Session{}, retryableError(protocol.PeerBusy)
			}
		}
	}
	controller, err := s.GetEndpoint(ctx, link.ControllerID)
	if err != nil {
		return Session{}, err
	}
	companion, err := s.GetEndpoint(ctx, link.CompanionID)
	if err != nil {
		return Session{}, err
	}
	if controller == nil || companion == nil {
		return Session{}, serviceError(protocol.Unauthenticated)
	}
	var controllerConnection, companionConnection Connection
	if controller.ConnectionID != "" {
		_, err = s.get(ctx, "CONNECTION", controller.ConnectionID, &controllerConnection)
		if err != nil {
			return Session{}, err
		}
	}
	if companion.ConnectionID != "" {
		_, err = s.get(ctx, "CONNECTION", companion.ConnectionID, &companionConnection)
		if err != nil {
			return Session{}, err
		}
	}
	staleLocks := map[string]struct{}{}
	for _, staleID := range []string{companion.ActiveSessionID, controllerConnection.SessionID, companionConnection.SessionID} {
		if staleID != "" {
			staleLocks[staleID] = struct{}{}
		}
	}
	repaired := false
	for staleID := range staleLocks {
		fixed, err := s.repairStaleSession(ctx, staleID, *link, now)
		if err != nil {
			return Session{}, err
		}
		repaired = repaired || fixed
	}
	if repaired {
		link, err = s.Link(ctx, linkID)
		if err != nil {
			return Session{}, err
		}
		if link == nil {
			return Session{}, serviceError(protocol.Unauthenticated)
		}
		controller, err = s.GetEndpoint(ctx, link.ControllerID)
		if err != nil {
			return Session{}, err
		}
		companion, err = s.GetEndpoint(ctx, link.CompanionID)
		if err != nil {
			return Session{}, err
		}
	}
	if link == nil || controller == nil || companion == nil {
		return Session{}, serviceError(protocol.Unauthenticated)
	}
	if controller.RevokedAt != 0 || controller.ConnectionID != connectionID {
		return Session{}, serviceError(protocol.Unauthenticated)
	}
	if companion.RevokedAt != 0 || companion.ConnectionID == "" {
		return Session{}, retryableError(protocol.PeerOffline)
	}
	session := Session{
		SessionID: sessionID, LinkID: linkID, ControllerID: controller.EndpointID, CompanionID: companion.EndpointID,
		ControllerConnectionID: connectionID, CompanionConnectionID: companion.ConnectionID,
		Status: "ACTIVE", CreatedAt: now, ExpiresAt: now + 2*60*60,
	}
	sessionItem, err := marshalItem("session", sessionID, session)
	if err != nil {
		return Session{}, err
	}
	linkValues, err := values(map[string]any{":sessionId": sessionID, ":active": "ACTIVE"})
	if err != nil {
		return Session{}, err
	}
	connectionValues, err := values(map[string]any{":sessionId": sessionID})
	if err != nil {
		return Session{}, err
	}
	controllerValues, err := values(map[string]any{":connectionId": connectionID})
	if err != nil {
		return Session{}, err
	}
	companionValues, err := values(map[string]any{":sessionId": sessionID, ":connectionId": companion.ConnectionID})
	if err != nil {
		return Session{}, err
	}
	operations := []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.tableName), Item: sessionItem, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("LINK", linkID), UpdateExpression: aws.String("SET activeSessionId = :sessionId"),
			ConditionExpression:      aws.String("#status = :active AND attribute_not_exists(activeSessionId)"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: linkValues,
		}},
		{ConditionCheck: &types.ConditionCheck{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", controller.EndpointID),
			ConditionExpression:       aws.String("connectionId = :connectionId AND attribute_not_exists(revokedAt)"),
			ExpressionAttributeValues: controllerValues,
		}},
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", companion.EndpointID),
			UpdateExpression:          aws.String("SET activeSessionId = :sessionId"),
			ConditionExpression:       aws.String("connectionId = :connectionId AND attribute_not_exists(activeSessionId) AND attribute_not_exists(revokedAt)"),
			ExpressionAttributeValues: companionValues,
		}},
	}
	for _, id := range []string{connectionID, companion.ConnectionID} {
		operations = append(operations, types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("CONNECTION", id), UpdateExpression: aws.String("SET sessionId = :sessionId"),
			ConditionExpression: aws.String("attribute_exists(pk) AND attribute_not_exists(sessionId)"), ExpressionAttributeValues: connectionValues,
		}})
	}
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
	if conditionalFailure(err) {
		return Session{}, retryableError(protocol.PeerBusy)
	}
	return session, err
}

func (s *DynamoStore) repairStaleSession(ctx context.Context, sessionID string, link Link, now int64) (bool, error) {
	var session Session
	found, err := s.get(ctx, "SESSION", sessionID, &session)
	if err != nil {
		return false, err
	}
	if found && session.Status == "ACTIVE" && !isExpired(session, now) {
		return false, nil
	}
	if found {
		_, err := s.CloseSession(ctx, sessionID, "", now)
		return true, err
	}
	controller, err := s.GetEndpoint(ctx, link.ControllerID)
	if err != nil {
		return false, err
	}
	companion, err := s.GetEndpoint(ctx, link.CompanionID)
	if err != nil {
		return false, err
	}
	cleanup := []error{
		s.clearIfEqual(ctx, "LINK", link.LinkID, "activeSessionId", sessionID),
		s.clearIfEqual(ctx, "ENDPOINT", link.CompanionID, "activeSessionId", sessionID),
	}
	if controller != nil && controller.ConnectionID != "" {
		cleanup = append(cleanup, s.clearIfEqual(ctx, "CONNECTION", controller.ConnectionID, "sessionId", sessionID))
	}
	if companion != nil && companion.ConnectionID != "" {
		cleanup = append(cleanup, s.clearIfEqual(ctx, "CONNECTION", companion.ConnectionID, "sessionId", sessionID))
	}
	return true, errors.Join(cleanup...)
}

func (s *DynamoStore) Session(ctx context.Context, sessionID string, now int64) (Session, error) {
	var session Session
	found, err := s.get(ctx, "SESSION", sessionID, &session)
	if err != nil {
		return Session{}, err
	}
	if !found || session.Status != "ACTIVE" || isExpired(session, now) {
		return Session{}, serviceError(protocol.SessionNotFound)
	}
	return session, nil
}

func (s *DynamoStore) CloseSession(ctx context.Context, sessionID, endpointID string, now int64) (*CloseSessionResult, error) {
	var session Session
	found, err := s.get(ctx, "SESSION", sessionID, &session)
	if err != nil || !found {
		return nil, err
	}
	if endpointID != "" && session.ControllerID != endpointID && session.CompanionID != endpointID {
		return nil, serviceError(protocol.Forbidden)
	}
	closedNow := false
	if session.Status == "ACTIVE" {
		expressionValues, err := values(map[string]any{":closed": "CLOSED", ":active": "ACTIVE", ":now": now})
		if err != nil {
			return nil, err
		}
		_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(s.tableName), Key: key("SESSION", sessionID),
			UpdateExpression:         aws.String("SET #status = :closed, closedAt = :now"),
			ConditionExpression:      aws.String("#status = :active"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		})
		if conditionalFailure(err) {
			found, err = s.get(ctx, "SESSION", sessionID, &session)
			if err != nil || !found {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else {
			session.Status, session.ClosedAt, closedNow = "CLOSED", now, true
		}
	}
	cleanup := []error{
		s.clearIfEqual(ctx, "LINK", session.LinkID, "activeSessionId", sessionID),
		s.clearIfEqual(ctx, "ENDPOINT", session.CompanionID, "activeSessionId", sessionID),
		s.clearIfEqual(ctx, "CONNECTION", session.ControllerConnectionID, "sessionId", sessionID),
		s.clearIfEqual(ctx, "CONNECTION", session.CompanionConnectionID, "sessionId", sessionID),
	}
	if err := errors.Join(cleanup...); err != nil {
		return nil, err
	}
	return &CloseSessionResult{Session: session, ClosedNow: closedNow}, nil
}

func (s *DynamoStore) clearIfEqual(ctx context.Context, kind, id, field, expected string) error {
	expressionValues, err := values(map[string]any{":expected": expected})
	if err != nil {
		return err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key(kind, id), UpdateExpression: aws.String("REMOVE " + field),
		ConditionExpression: aws.String(field + " = :expected"), ExpressionAttributeValues: expressionValues,
	})
	if conditionalFailure(err) {
		return nil
	}
	return err
}
