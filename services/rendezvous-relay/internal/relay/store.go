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

const (
	meta                                = "META"
	defaultPairActivationsPerSourceHour = int64(10)
	pairActivationsPerDay               = int64(10_000)
	minuteRateWindowSeconds             = int64(60)
	hourlyRateWindowSeconds             = int64(60 * 60)
	dailyRateWindowSeconds              = int64(24 * 60 * 60)
)

type Store interface {
	GetEndpoint(context.Context, string) (*Endpoint, error)
	Connect(context.Context, Connection, string) (*CloseSessionResult, error)
	Disconnect(context.Context, string, int64) (*DisconnectResult, error)
	Connection(context.Context, string, int64) (Connection, error)
	RateLimit(context.Context, string, string, int64, int64) error
	CreatePair(context.Context, Pair) error
	PairByID(context.Context, string, int64) (Pair, error)
	JoinPair(context.Context, string, string, PairSide, int64) (Pair, error)
	CommitPair(context.Context, string, PairCommit, string, int64) (CommitPairResult, error)
	CancelPair(context.Context, string, string, int64) (*Pair, error)
	Link(context.Context, string) (*Link, error)
	RevokeLink(context.Context, string, string, string, int64) (RevokeLinkResult, error)
	RotateEndpoint(context.Context, string, string, string, int64) error
	RevokeEndpoint(context.Context, string, string, int64) (RevokeEndpointResult, error)
	OpenSession(context.Context, string, string, string, string, int64) (Session, error)
	Session(context.Context, string, int64) (Session, error)
	CloseSession(context.Context, string, string, string, int64) (*CloseSessionResult, error)
}

type DynamoAPI interface {
	GetItem(context.Context, *dynamodb.GetItemInput, ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
	UpdateItem(context.Context, *dynamodb.UpdateItemInput, ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

type DynamoStore struct {
	tableName                    string
	db                           DynamoAPI
	pairActivationsPerSourceHour int64
}

func NewDynamoStore(tableName string, db DynamoAPI, sourceActivationLimits ...int64) *DynamoStore {
	limit := defaultPairActivationsPerSourceHour
	if len(sourceActivationLimits) == 1 {
		limit = sourceActivationLimits[0]
	}
	if len(sourceActivationLimits) > 1 || limit < 1 || limit > pairActivationsPerDay {
		panic("invalid per-source pair activation limit")
	}
	return &DynamoStore{tableName: tableName, db: db, pairActivationsPerSourceHour: limit}
}

func key(prefix, id string) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: itemKey(prefix, id)},
		"sk": &types.AttributeValueMemberS{Value: meta},
	}
}

func itemKey(prefix, id string) string { return strings.ToUpper(prefix) + "#" + id }

func marshalItem(kind, id string, value any) (map[string]types.AttributeValue, error) {
	item, err := attributevalue.MarshalMap(value)
	if err != nil {
		return nil, err
	}
	item["pk"] = &types.AttributeValueMemberS{Value: itemKey(kind, id)}
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
	var conditional *types.ConditionalCheckFailedException
	if errors.As(err, &conditional) {
		return true
	}
	var cancelled *types.TransactionCanceledException
	if !errors.As(err, &cancelled) {
		return false
	}
	found := false
	for _, reason := range cancelled.CancellationReasons {
		switch aws.ToString(reason.Code) {
		case "", "None":
		case "ConditionalCheckFailed":
			found = true
		default:
			return false
		}
	}
	return found
}

func transactionConditionalFailureAt(err error, index int) bool {
	var cancelled *types.TransactionCanceledException
	if !errors.As(err, &cancelled) || index < 0 || index >= len(cancelled.CancellationReasons) ||
		aws.ToString(cancelled.CancellationReasons[index].Code) != "ConditionalCheckFailed" {
		return false
	}
	for _, reason := range cancelled.CancellationReasons {
		switch aws.ToString(reason.Code) {
		case "", "None", "ConditionalCheckFailed":
		default:
			return false
		}
	}
	return true
}

func (s *DynamoStore) GetEndpoint(ctx context.Context, endpointID string) (*Endpoint, error) {
	var endpoint Endpoint
	found, err := s.get(ctx, "ENDPOINT", endpointID, &endpoint)
	if err != nil || !found {
		return nil, err
	}
	return &endpoint, nil
}

func (s *DynamoStore) currentEndpoint(ctx context.Context, endpointID, connectionID string) (*Endpoint, error) {
	if endpointID == "" || connectionID == "" {
		return nil, serviceError(protocol.Unauthenticated)
	}
	endpoint, err := s.GetEndpoint(ctx, endpointID)
	if err != nil {
		return nil, err
	}
	if endpoint == nil || endpoint.RevokedAt != 0 || endpoint.ConnectionID != connectionID {
		return nil, serviceError(protocol.Unauthenticated)
	}
	return endpoint, nil
}

func (s *DynamoStore) Connect(ctx context.Context, connection Connection, credentialHash string) (*CloseSessionResult, error) {
	if connection.AuthMode == "endpoint" && (connection.EndpointID == "" || credentialHash == "") ||
		connection.AuthMode == "pairing" && connection.EndpointID != "" {
		return nil, serviceError(protocol.Unauthenticated)
	}
	item, err := marshalItem("connection", connection.ConnectionID, connection)
	if err != nil {
		return nil, err
	}
	if connection.EndpointID == "" {
		_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{{Put: &types.Put{
			TableName: aws.String(s.tableName), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
		}}}})
		if conditionalFailure(err) {
			return nil, serviceError(protocol.Unauthenticated)
		}
		return nil, err
	}

	for attempt := 0; attempt < 5; attempt++ {
		endpoint, err := s.GetEndpoint(ctx, connection.EndpointID)
		if err != nil {
			return nil, err
		}
		if endpoint == nil || endpoint.RevokedAt != 0 || endpoint.CredentialHash != credentialHash {
			return nil, serviceError(protocol.Unauthenticated)
		}
		sameConnection := false
		if endpoint.ConnectionID == connection.ConnectionID {
			var existing Connection
			found, err := s.get(ctx, "CONNECTION", connection.ConnectionID, &existing)
			if err != nil {
				return nil, err
			}
			if found && existing.AuthMode == connection.AuthMode && existing.EndpointID == connection.EndpointID {
				sameConnection = true
			}
		}

		var session Session
		hasSession := false
		if endpoint.ActiveSessionID != "" {
			hasSession, err = s.get(ctx, "SESSION", endpoint.ActiveSessionID, &session)
			if err != nil {
				return nil, err
			}
			if sameConnection && hasSession && session.Status == "ACTIVE" &&
				(session.ControllerID == endpoint.EndpointID && session.ControllerConnectionID == connection.ConnectionID ||
					session.CompanionID == endpoint.EndpointID && session.CompanionConnectionID == connection.ConnectionID) {
				return nil, nil
			}
		} else if sameConnection {
			return nil, nil
		}

		condition := "attribute_not_exists(connectionId)"
		expressionInput := map[string]any{
			":connectionId": connection.ConnectionID, ":now": connection.ConnectedAt, ":credentialHash": credentialHash,
		}
		if endpoint.ConnectionID != "" {
			condition = "connectionId = :oldConnectionId"
			expressionInput[":oldConnectionId"] = endpoint.ConnectionID
		}
		updateExpression := "SET connectionId = :connectionId, updatedAt = :now"
		if endpoint.ActiveSessionID != "" {
			condition += " AND activeSessionId = :sessionId"
			expressionInput[":sessionId"] = endpoint.ActiveSessionID
			updateExpression += " REMOVE activeSessionId"
		} else {
			condition += " AND attribute_not_exists(activeSessionId)"
		}
		expressionValues, err := values(expressionInput)
		if err != nil {
			return nil, err
		}
		operations := make([]types.TransactWriteItem, 0, 3)
		if !sameConnection {
			operations = append(operations, types.TransactWriteItem{Put: &types.Put{
				TableName: aws.String(s.tableName), Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)"),
			}})
		}
		operations = append(operations, types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", connection.EndpointID),
			UpdateExpression:          aws.String(updateExpression),
			ConditionExpression:       aws.String("attribute_exists(pk) AND attribute_not_exists(revokedAt) AND credentialHash = :credentialHash AND " + condition),
			ExpressionAttributeValues: expressionValues,
		}})
		if endpoint.ConnectionID != "" && endpoint.ConnectionID != connection.ConnectionID {
			operations = append(operations, types.TransactWriteItem{Delete: &types.Delete{
				TableName: aws.String(s.tableName), Key: key("CONNECTION", endpoint.ConnectionID),
			}})
		}
		if endpoint.ActiveSessionID != "" && hasSession &&
			(session.ControllerID == endpoint.EndpointID || session.CompanionID == endpoint.EndpointID) {
			closed, err := s.transactSessionTransition(ctx, session, connection.ConnectedAt, operations, map[string]bool{
				itemKey("ENDPOINT", endpoint.EndpointID): true,
			}, nil)
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if closed {
				return &CloseSessionResult{Session: closedSession(session, connection.ConnectedAt), ClosedNow: true}, nil
			}
			return nil, nil
		}
		_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
		if conditionalFailure(err) {
			continue
		}
		return nil, err
	}
	return nil, retryableError(protocol.Conflict)
}

func (s *DynamoStore) Disconnect(ctx context.Context, connectionID string, now int64) (*DisconnectResult, error) {
	for attempt := 0; attempt < 5; attempt++ {
		var connection Connection
		found, err := s.get(ctx, "CONNECTION", connectionID, &connection)
		if err != nil || !found {
			return nil, err
		}
		result := &DisconnectResult{Connection: connection}
		deleteConnection := types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(s.tableName), Key: key("CONNECTION", connectionID),
			ConditionExpression: aws.String("attribute_exists(pk)"),
		}}
		if connection.EndpointID == "" {
			operations := []types.TransactWriteItem{deleteConnection}
			if connection.PairingID != "" {
				var pair Pair
				pairFound, readErr := s.get(ctx, "PAIR", connection.PairingID, &pair)
				if readErr != nil {
					return nil, readErr
				}
				member := pair.SideA.ConnectionID == connectionID || pair.SideB != nil && pair.SideB.ConnectionID == connectionID
				if pairFound && member && pair.Status != "ACTIVE" && pair.Status != "CLOSED" {
					expressionValues, valueErr := values(map[string]any{
						":active": "ACTIVE", ":closed": "CLOSED", ":connectionId": connectionID,
					})
					if valueErr != nil {
						return nil, valueErr
					}
					operations = append(operations, types.TransactWriteItem{Update: &types.Update{
						TableName: aws.String(s.tableName), Key: key("PAIR", connection.PairingID),
						UpdateExpression:          aws.String("SET #status = :closed"),
						ConditionExpression:       aws.String("#status <> :active AND (sideA.connectionId = :connectionId OR sideB.connectionId = :connectionId)"),
						ExpressionAttributeNames:  map[string]string{"#status": "status"},
						ExpressionAttributeValues: expressionValues,
					}})
				}
			}
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
			if conditionalFailure(err) {
				continue
			}
			return result, err
		}

		endpoint, err := s.GetEndpoint(ctx, connection.EndpointID)
		if err != nil {
			return nil, err
		}
		if endpoint == nil || endpoint.ConnectionID != connectionID {
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{deleteConnection}})
			if conditionalFailure(err) {
				continue
			}
			return result, err
		}

		condition := "connectionId = :connectionId AND attribute_not_exists(activeSessionId)"
		input := map[string]any{":connectionId": connectionID}
		if endpoint.ActiveSessionID != "" {
			condition = "connectionId = :connectionId AND activeSessionId = :sessionId"
			input[":sessionId"] = endpoint.ActiveSessionID
		}
		expressionValues, err := values(input)
		if err != nil {
			return nil, err
		}
		removeEndpoint := types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", connection.EndpointID),
			UpdateExpression: aws.String("REMOVE connectionId, activeSessionId"), ConditionExpression: aws.String(condition),
			ExpressionAttributeValues: expressionValues,
		}}
		operations := []types.TransactWriteItem{deleteConnection, removeEndpoint}
		if endpoint.ActiveSessionID == "" {
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
			if conditionalFailure(err) {
				continue
			}
			return result, err
		}

		var session Session
		found, err = s.get(ctx, "SESSION", endpoint.ActiveSessionID, &session)
		if err != nil {
			return nil, err
		}
		if found && (session.ControllerConnectionID == connectionID || session.CompanionConnectionID == connectionID) {
			closed, err := s.transactSessionTransition(ctx, session, now, operations, map[string]bool{
				itemKey("ENDPOINT", connection.EndpointID): true,
			}, nil)
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if closed {
				result.Session = &CloseSessionResult{Session: closedSession(session, now), ClosedNow: true}
			}
			return result, nil
		}
		_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
		if conditionalFailure(err) {
			continue
		}
		return result, err
	}
	return nil, retryableError(protocol.Conflict)
}

func (s *DynamoStore) Connection(ctx context.Context, connectionID string, now int64) (Connection, error) {
	var connection Connection
	found, err := s.get(ctx, "CONNECTION", connectionID, &connection)
	if err != nil {
		return Connection{}, err
	}
	if !found || connection.ExpiresAt <= now {
		return Connection{}, serviceError(protocol.Unauthenticated)
	}
	return connection, nil
}

func (s *DynamoStore) RateLimit(ctx context.Context, sourceKey, action string, limit, now int64) error {
	return s.rateLimit(ctx, sourceKey, action, limit, minuteRateWindowSeconds, now)
}

func (s *DynamoStore) rateLimitUpdate(sourceKey, action string, limit, windowSeconds, now int64) (*types.Update, int64, error) {
	bucket := now / windowSeconds
	expressionValues, err := values(map[string]any{
		":expiresAt": (bucket + 2) * windowSeconds, ":one": int64(1), ":limit": limit,
	})
	if err != nil {
		return nil, 0, err
	}
	retryAfter := min(((bucket+1)*windowSeconds-now)*1_000, int64(3_600_000))
	return &types.Update{
		TableName: aws.String(s.tableName), Key: key("RATE", fmt.Sprintf("%s#%s#%d", sourceKey, action, bucket)),
		UpdateExpression:         aws.String("SET expiresAt = :expiresAt ADD #count :one"),
		ConditionExpression:      aws.String("attribute_not_exists(#count) OR #count < :limit"),
		ExpressionAttributeNames: map[string]string{"#count": "count"}, ExpressionAttributeValues: expressionValues,
	}, retryAfter, nil
}

func (s *DynamoStore) rateLimit(ctx context.Context, sourceKey, action string, limit, windowSeconds, now int64) error {
	update, retryAfter, err := s.rateLimitUpdate(sourceKey, action, limit, windowSeconds, now)
	if err != nil {
		return err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: update.TableName, Key: update.Key, UpdateExpression: update.UpdateExpression,
		ConditionExpression: update.ConditionExpression, ExpressionAttributeNames: update.ExpressionAttributeNames,
		ExpressionAttributeValues: update.ExpressionAttributeValues,
	})
	if conditionalFailure(err) {
		return &ServiceError{Code: protocol.RateLimited, Retryable: true, RetryAfterMS: &retryAfter}
	}
	return err
}

type pairPointer struct {
	PairID        string `dynamodbav:"pairId"`
	Locator       string `dynamodbav:"locator,omitempty"`
	JoinTokenHash string `dynamodbav:"joinTokenHash,omitempty"`
	ExpiresAt     int64  `dynamodbav:"expiresAt"`
}

func (s *DynamoStore) CreatePair(ctx context.Context, pair Pair) error {
	if (pair.Locator == "") == (pair.JoinTokenHash == "") {
		return serviceError(protocol.InvalidMessage)
	}
	pairItem, err := marshalItem("pair", pair.PairID, pair)
	if err != nil {
		return err
	}
	pointerKind, pointerID := "locator", pair.Locator
	if pair.JoinTokenHash != "" {
		pointerKind, pointerID = "join", pair.JoinTokenHash
	}
	pointerItem, err := marshalItem(pointerKind, pointerID, pairPointer{
		PairID: pair.PairID, Locator: pair.Locator, JoinTokenHash: pair.JoinTokenHash, ExpiresAt: pair.ExpiresAt,
	})
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
	return s.pairByAdmission(ctx, "LOCATOR", locator, now)
}

func (s *DynamoStore) pairByJoinTokenHash(ctx context.Context, joinTokenHash string, now int64) (Pair, error) {
	return s.pairByAdmission(ctx, "JOIN", joinTokenHash, now)
}

func (s *DynamoStore) pairByAdmission(ctx context.Context, kind, value string, now int64) (Pair, error) {
	var pointer pairPointer
	found, err := s.get(ctx, kind, value, &pointer)
	if err != nil {
		return Pair{}, err
	}
	if !found || pointer.ExpiresAt <= now {
		return Pair{}, serviceError(protocol.PairExpired)
	}
	pair, err := s.PairByID(ctx, pointer.PairID, now)
	if err != nil {
		return Pair{}, err
	}
	legacy := kind == "LOCATOR"
	if legacy && (pointer.Locator != value || pair.Locator != value || pointer.JoinTokenHash != "" || pair.JoinTokenHash != "") ||
		!legacy && (pointer.JoinTokenHash != value || pair.JoinTokenHash != value || pointer.Locator != "" || pair.Locator != "") {
		return Pair{}, serviceError(protocol.PairUnavailable)
	}
	return pair, nil
}

func (s *DynamoStore) PairByID(ctx context.Context, pairID string, now int64) (Pair, error) {
	var pair Pair
	found, err := s.get(ctx, "PAIR", pairID, &pair)
	if err != nil {
		return Pair{}, err
	}
	if !found || pair.ExpiresAt <= now {
		return Pair{}, serviceError(protocol.PairExpired)
	}
	if pair.PairID != pairID {
		return Pair{}, serviceError(protocol.PairUnavailable)
	}
	return pair, nil
}

func (s *DynamoStore) JoinPair(ctx context.Context, locator, joinTokenHash string, side PairSide, now int64) (Pair, error) {
	if (locator == "") == (joinTokenHash == "") {
		return Pair{}, serviceError(protocol.InvalidMessage)
	}
	var pair Pair
	var err error
	if locator != "" {
		pair, err = s.PairByLocator(ctx, locator, now)
	} else {
		pair, err = s.pairByJoinTokenHash(ctx, joinTokenHash, now)
	}
	if err != nil {
		return Pair{}, err
	}
	if pair.Status != "OPEN" || pair.SideB != nil {
		return Pair{}, serviceError(protocol.PairFull)
	}
	admission, admissionName, otherAdmissionName := locator, "locator", "joinTokenHash"
	if joinTokenHash != "" {
		admission, admissionName, otherAdmissionName = joinTokenHash, "joinTokenHash", "locator"
	}
	admissionCondition := "#admission = :admission AND attribute_not_exists(#otherAdmission)"
	updateValues, err := values(map[string]any{
		":side": side, ":ready": "READY", ":open": "OPEN", ":now": now, ":admission": admission,
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
			TableName: aws.String(s.tableName), Key: key("PAIR", pair.PairID),
			UpdateExpression:    aws.String("SET sideB = :side, #status = :ready"),
			ConditionExpression: aws.String("#status = :open AND expiresAt > :now AND attribute_not_exists(sideB) AND " + admissionCondition),
			ExpressionAttributeNames: map[string]string{
				"#admission": admissionName, "#otherAdmission": otherAdmissionName, "#status": "status",
			},
			ExpressionAttributeValues: updateValues,
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
	pair.SideB, pair.Status = &side, "READY"
	return pair, nil
}

func (s *DynamoStore) endpointWrite(endpoint Endpoint) (types.TransactWriteItem, error) {
	expressionValues, err := values(map[string]any{
		":endpointId": endpoint.EndpointID, ":credentialHash": endpoint.CredentialHash, ":role": endpoint.Role,
		":createdAt": endpoint.CreatedAt, ":updatedAt": endpoint.UpdatedAt, ":kind": "endpoint",
	})
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{Update: &types.Update{
		TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpoint.EndpointID),
		UpdateExpression: aws.String(
			"SET endpointId = if_not_exists(endpointId, :endpointId), " +
				"credentialHash = if_not_exists(credentialHash, :credentialHash), " +
				"#role = if_not_exists(#role, :role), " +
				"createdAt = if_not_exists(createdAt, :createdAt), " +
				"updatedAt = if_not_exists(updatedAt, :updatedAt), " +
				"#kind = if_not_exists(#kind, :kind)",
		),
		ConditionExpression: aws.String(
			"attribute_not_exists(pk) OR (credentialHash = :credentialHash AND #role = :role AND attribute_not_exists(revokedAt))",
		),
		ExpressionAttributeNames: map[string]string{"#kind": "kind", "#role": "role"}, ExpressionAttributeValues: expressionValues,
	}}, nil
}

func (s *DynamoStore) CommitPair(ctx context.Context, pairID string, commit PairCommit, sourceKey string, now int64) (CommitPairResult, error) {
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
			":commit": commit, ":half": "HALF_COMMITTED", ":ready": "READY", ":now": now,
		})
		if err != nil {
			return CommitPairResult{}, err
		}
		_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
			TableName: aws.String(s.tableName), Key: key("PAIR", pair.PairID),
			UpdateExpression:         aws.String("SET " + ownField + " = :commit, #status = :half"),
			ConditionExpression:      aws.String("#status = :ready AND expiresAt > :now AND attribute_not_exists(" + ownField + ")"),
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
		pair.Status = "HALF_COMMITTED"
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
	if sourceKey == "" {
		return CommitPairResult{}, errors.New("pair activation source key is required")
	}
	endpoints := []Endpoint{
		{EndpointID: first.Self.EndpointID, CredentialHash: first.Self.CredentialHash, Role: first.Self.Role, CreatedAt: now, UpdatedAt: now},
		{EndpointID: second.Self.EndpointID, CredentialHash: second.Self.CredentialHash, Role: second.Self.Role, CreatedAt: now, UpdatedAt: now},
	}
	endpointWrites := make([]types.TransactWriteItem, 0, 2)
	for _, endpoint := range endpoints {
		write, err := s.endpointWrite(endpoint)
		if err != nil {
			return CommitPairResult{}, err
		}
		endpointWrites = append(endpointWrites, write)
	}
	expressionValues, err := values(map[string]any{
		":commit": commit, ":active": "ACTIVE", ":half": "HALF_COMMITTED",
		":now": now,
	})
	if err != nil {
		return CommitPairResult{}, err
	}
	linkItem, err := marshalItem("link", link.LinkID, link)
	if err != nil {
		return CommitPairResult{}, err
	}
	sourceRateUpdate, sourceRetryAfter, err := s.rateLimitUpdate(
		sourceKey, "pair.activate", s.pairActivationsPerSourceHour, hourlyRateWindowSeconds, now,
	)
	if err != nil {
		return CommitPairResult{}, err
	}
	globalRateUpdate, globalRetryAfter, err := s.rateLimitUpdate("global", "pair.activate", pairActivationsPerDay, dailyRateWindowSeconds, now)
	if err != nil {
		return CommitPairResult{}, err
	}
	operations := []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("PAIR", pair.PairID),
			UpdateExpression:         aws.String("SET " + ownField + " = :commit, #status = :active"),
			ConditionExpression:      aws.String("#status = :half AND expiresAt > :now AND attribute_not_exists(" + ownField + ")"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		}},
		{Put: &types.Put{TableName: aws.String(s.tableName), Item: linkItem, ConditionExpression: aws.String("attribute_not_exists(pk)")}},
	}
	operations = append(operations, endpointWrites...)
	sourceRateIndex := len(operations)
	operations = append(operations, types.TransactWriteItem{Update: sourceRateUpdate})
	globalRateIndex := len(operations)
	operations = append(operations, types.TransactWriteItem{Update: globalRateUpdate})
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
	// A quota cancellation proves the atomic activation did not occur, so clients can discard staged credentials.
	if transactionConditionalFailureAt(err, sourceRateIndex) {
		return CommitPairResult{}, &ServiceError{Code: protocol.RateLimited, RetryAfterMS: &sourceRetryAfter}
	}
	if transactionConditionalFailureAt(err, globalRateIndex) {
		return CommitPairResult{}, &ServiceError{Code: protocol.RateLimited, RetryAfterMS: &globalRetryAfter}
	}
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
	pair.Status = "ACTIVE"
	return CommitPairResult{Pair: pair, Link: &link, ActivatedNow: true}, nil
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
	expressionValues, err := values(map[string]any{":closed": "CLOSED", ":active": "ACTIVE"})
	if err != nil {
		return nil, err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("PAIR", pair.PairID),
		UpdateExpression:         aws.String("SET #status = :closed"),
		ConditionExpression:      aws.String("#status <> :active"),
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
	pair.Status = "CLOSED"
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

func (s *DynamoStore) endpointFence(endpointID, connectionID string) (types.TransactWriteItem, error) {
	expressionValues, err := values(map[string]any{":connectionId": connectionID})
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
		ConditionExpression:       aws.String("connectionId = :connectionId AND attribute_not_exists(revokedAt)"),
		ExpressionAttributeValues: expressionValues,
	}}, nil
}

func (s *DynamoStore) RevokeLink(ctx context.Context, linkID, endpointID, connectionID string, now int64) (RevokeLinkResult, error) {
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := s.currentEndpoint(ctx, endpointID, connectionID); err != nil {
			return RevokeLinkResult{}, err
		}
		link, err := s.Link(ctx, linkID)
		if err != nil {
			return RevokeLinkResult{}, err
		}
		if link == nil || link.ControllerID != endpointID && link.CompanionID != endpointID {
			return RevokeLinkResult{}, serviceError(protocol.Forbidden)
		}
		result := RevokeLinkResult{Link: *link}
		if link.Status == "REVOKED" {
			if link.ActiveSessionID != "" {
				closed, err := s.CloseSession(ctx, link.ActiveSessionID, endpointID, connectionID, now)
				if err != nil {
					return RevokeLinkResult{}, err
				}
				if closed != nil && closed.ClosedNow {
					result.Session = closed
				}
				_ = s.clearIfEqual(ctx, "LINK", linkID, "activeSessionId", link.ActiveSessionID)
				result.Link.ActiveSessionID = ""
			}
			return result, nil
		}

		condition := "#status = :active AND attribute_not_exists(activeSessionId)"
		input := map[string]any{":revoked": "REVOKED", ":active": "ACTIVE", ":now": now}
		if link.ActiveSessionID != "" {
			condition = "#status = :active AND activeSessionId = :sessionId"
			input[":sessionId"] = link.ActiveSessionID
		}
		expressionValues, err := values(input)
		if err != nil {
			return RevokeLinkResult{}, err
		}
		revoke := types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("LINK", linkID),
			UpdateExpression:         aws.String("SET #status = :revoked, revokedAt = :now REMOVE activeSessionId"),
			ConditionExpression:      aws.String(condition),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		}}
		if link.ActiveSessionID == "" {
			fence, fenceErr := s.endpointFence(endpointID, connectionID)
			if fenceErr != nil {
				return RevokeLinkResult{}, fenceErr
			}
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{revoke, fence}})
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return RevokeLinkResult{}, err
			}
			result.Link.Status, result.Link.RevokedAt = "REVOKED", now
			return result, nil
		}

		var session Session
		found, err := s.get(ctx, "SESSION", link.ActiveSessionID, &session)
		if err != nil {
			return RevokeLinkResult{}, err
		}
		if !found || session.LinkID != linkID {
			session = Session{
				SessionID: link.ActiveSessionID, LinkID: linkID, ControllerID: link.ControllerID,
				CompanionID: link.CompanionID, Status: "CLOSED",
			}
		}
		closed, err := s.transactSessionTransition(ctx, session, now, []types.TransactWriteItem{revoke}, map[string]bool{
			itemKey("LINK", linkID): true,
		}, map[string]string{endpointID: connectionID})
		if conditionalFailure(err) {
			continue
		}
		if err != nil {
			return RevokeLinkResult{}, err
		}
		result.Link.Status, result.Link.RevokedAt, result.Link.ActiveSessionID = "REVOKED", now, ""
		if closed {
			result.Session = &CloseSessionResult{Session: closedSession(session, now), ClosedNow: true}
		}
		return result, nil
	}
	return RevokeLinkResult{}, retryableError(protocol.Conflict)
}

func (s *DynamoStore) RotateEndpoint(ctx context.Context, endpointID, connectionID, credentialHash string, now int64) error {
	expressionValues, err := values(map[string]any{
		":connectionId": connectionID, ":credentialHash": credentialHash, ":now": now,
	})
	if err != nil {
		return err
	}
	_, err = s.db.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
		UpdateExpression:          aws.String("SET credentialHash = :credentialHash, updatedAt = :now"),
		ConditionExpression:       aws.String("attribute_exists(pk) AND attribute_not_exists(revokedAt) AND connectionId = :connectionId"),
		ExpressionAttributeValues: expressionValues,
	})
	if conditionalFailure(err) {
		return serviceError(protocol.Unauthenticated)
	}
	return err
}

func (s *DynamoStore) RevokeEndpoint(ctx context.Context, endpointID, connectionID string, now int64) (RevokeEndpointResult, error) {
	for attempt := 0; attempt < 5; attempt++ {
		endpoint, err := s.currentEndpoint(ctx, endpointID, connectionID)
		if err != nil {
			return RevokeEndpointResult{}, err
		}

		condition := "attribute_not_exists(revokedAt) AND connectionId = :connectionId AND attribute_not_exists(activeSessionId)"
		input := map[string]any{":connectionId": connectionID, ":now": now}
		if endpoint.ActiveSessionID != "" {
			condition = "attribute_not_exists(revokedAt) AND connectionId = :connectionId AND activeSessionId = :sessionId"
			input[":sessionId"] = endpoint.ActiveSessionID
		}
		expressionValues, err := values(input)
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		revoke := types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
			UpdateExpression:          aws.String("SET revokedAt = :now, updatedAt = :now REMOVE connectionId, activeSessionId, credentialHash"),
			ConditionExpression:       aws.String(condition),
			ExpressionAttributeValues: expressionValues,
		}}
		deleteConnection := types.TransactWriteItem{Delete: &types.Delete{
			TableName: aws.String(s.tableName), Key: key("CONNECTION", connectionID),
		}}
		result := RevokeEndpointResult{Endpoint: *endpoint}
		result.Endpoint.CredentialHash = ""
		if endpoint.ActiveSessionID == "" {
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{revoke, deleteConnection}})
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return RevokeEndpointResult{}, err
			}
			result.Endpoint.ConnectionID, result.Endpoint.ActiveSessionID = "", ""
			result.Endpoint.RevokedAt, result.Endpoint.UpdatedAt = now, now
			return result, nil
		}

		var session Session
		found, err := s.get(ctx, "SESSION", endpoint.ActiveSessionID, &session)
		if err != nil {
			return RevokeEndpointResult{}, err
		}
		if !found || session.ControllerID != endpointID && session.CompanionID != endpointID {
			_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{revoke, deleteConnection}})
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return RevokeEndpointResult{}, err
			}
		} else {
			closed, err := s.transactSessionTransition(ctx, session, now, []types.TransactWriteItem{revoke, deleteConnection}, map[string]bool{
				itemKey("ENDPOINT", endpointID): true,
			}, nil)
			if conditionalFailure(err) {
				continue
			}
			if err != nil {
				return RevokeEndpointResult{}, err
			}
			if closed {
				result.Session = &CloseSessionResult{Session: closedSession(session, now), ClosedNow: true}
			}
		}
		result.Endpoint.ConnectionID, result.Endpoint.ActiveSessionID = "", ""
		result.Endpoint.RevokedAt, result.Endpoint.UpdatedAt = now, now
		return result, nil
	}
	return RevokeEndpointResult{}, retryableError(protocol.Conflict)
}

func (s *DynamoStore) OpenSession(ctx context.Context, linkID, endpointID, connectionID, sessionID string, now int64) (Session, error) {
	for attempt := 0; attempt < 5; attempt++ {
		link, err := s.Link(ctx, linkID)
		if err != nil {
			return Session{}, err
		}
		if link == nil || link.Status != "ACTIVE" || link.ControllerID != endpointID {
			return Session{}, serviceError(protocol.Forbidden)
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

		staleLocks := map[string]struct{}{}
		for _, staleID := range []string{link.ActiveSessionID, controller.ActiveSessionID, companion.ActiveSessionID} {
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
			if !fixed {
				return Session{}, retryableError(protocol.PeerBusy)
			}
			repaired = true
		}
		if repaired {
			continue
		}
		if controller.RevokedAt != 0 || controller.ConnectionID != connectionID {
			return Session{}, serviceError(protocol.Unauthenticated)
		}
		if companion.RevokedAt != 0 || companion.ConnectionID == "" || companion.ConnectionID == connectionID {
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
		controllerValues, err := values(map[string]any{":sessionId": sessionID, ":connectionId": connectionID})
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
			{Update: &types.Update{
				TableName: aws.String(s.tableName), Key: key("ENDPOINT", controller.EndpointID),
				UpdateExpression:          aws.String("SET activeSessionId = :sessionId"),
				ConditionExpression:       aws.String("connectionId = :connectionId AND attribute_not_exists(activeSessionId) AND attribute_not_exists(revokedAt)"),
				ExpressionAttributeValues: controllerValues,
			}},
			{Update: &types.Update{
				TableName: aws.String(s.tableName), Key: key("ENDPOINT", companion.EndpointID),
				UpdateExpression:          aws.String("SET activeSessionId = :sessionId"),
				ConditionExpression:       aws.String("connectionId = :connectionId AND attribute_not_exists(activeSessionId) AND attribute_not_exists(revokedAt)"),
				ExpressionAttributeValues: companionValues,
			}},
		}
		_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
		if conditionalFailure(err) {
			continue
		}
		return session, err
	}
	return Session{}, retryableError(protocol.PeerBusy)
}

func (s *DynamoStore) repairStaleSession(ctx context.Context, sessionID string, link Link, now int64) (bool, error) {
	var session Session
	found, err := s.get(ctx, "SESSION", sessionID, &session)
	if err != nil {
		return false, err
	}
	if found && session.Status == "ACTIVE" && session.ExpiresAt > now {
		return false, nil
	}
	if found {
		_, err := s.CloseSession(ctx, sessionID, "", "", now)
		return true, err
	}
	_, err = s.transactSessionTransition(ctx, Session{
		SessionID: sessionID, LinkID: link.LinkID, ControllerID: link.ControllerID,
		CompanionID: link.CompanionID, Status: "CLOSED",
	}, now, nil, nil, nil)
	if conditionalFailure(err) {
		return true, nil
	}
	return true, err
}

func (s *DynamoStore) Session(ctx context.Context, sessionID string, now int64) (Session, error) {
	var session Session
	found, err := s.get(ctx, "SESSION", sessionID, &session)
	if err != nil {
		return Session{}, err
	}
	if !found || session.Status != "ACTIVE" {
		return Session{}, serviceError(protocol.SessionNotFound)
	}
	if session.ExpiresAt <= now {
		if _, err := s.CloseSession(ctx, sessionID, "", "", now); err != nil {
			return Session{}, err
		}
		return Session{}, serviceError(protocol.SessionNotFound)
	}
	return session, nil
}

func (s *DynamoStore) CloseSession(ctx context.Context, sessionID, endpointID, connectionID string, now int64) (*CloseSessionResult, error) {
	for attempt := 0; attempt < 5; attempt++ {
		if endpointID != "" {
			if _, err := s.currentEndpoint(ctx, endpointID, connectionID); err != nil {
				return nil, err
			}
		} else if connectionID != "" {
			return nil, serviceError(protocol.Unauthenticated)
		}
		var session Session
		found, err := s.get(ctx, "SESSION", sessionID, &session)
		if err != nil || !found {
			return nil, err
		}
		if endpointID != "" && session.ControllerID != endpointID && session.CompanionID != endpointID {
			return nil, serviceError(protocol.Forbidden)
		}
		var fences map[string]string
		if endpointID != "" {
			fences = map[string]string{endpointID: connectionID}
		}
		closed, err := s.transactSessionTransition(ctx, session, now, nil, nil, fences)
		if conditionalFailure(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if closed {
			session = closedSession(session, now)
		}
		return &CloseSessionResult{Session: session, ClosedNow: closed}, nil
	}
	return nil, retryableError(protocol.Conflict)
}

func closedSession(session Session, now int64) Session {
	session.Status, session.ClosedAt = "CLOSED", now
	return session
}

func (s *DynamoStore) transactSessionTransition(
	ctx context.Context,
	session Session,
	now int64,
	prefix []types.TransactWriteItem,
	omit map[string]bool,
	fences map[string]string,
) (bool, error) {
	operations := append([]types.TransactWriteItem(nil), prefix...)
	closing := session.Status == "ACTIVE"
	if closing {
		expressionValues, err := values(map[string]any{":closed": "CLOSED", ":active": "ACTIVE", ":now": now})
		if err != nil {
			return false, err
		}
		operations = append(operations, types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: key("SESSION", session.SessionID),
			UpdateExpression:         aws.String("SET #status = :closed, closedAt = :now"),
			ConditionExpression:      aws.String("#status = :active"),
			ExpressionAttributeNames: map[string]string{"#status": "status"}, ExpressionAttributeValues: expressionValues,
		}})
	}
	pointerValues, err := values(map[string]any{":sessionId": session.SessionID})
	if err != nil {
		return false, err
	}
	if !omit[itemKey("LINK", session.LinkID)] {
		link, err := s.Link(ctx, session.LinkID)
		if err != nil {
			return false, err
		}
		if link != nil && link.ActiveSessionID == session.SessionID {
			operations = append(operations, types.TransactWriteItem{Update: &types.Update{
				TableName: aws.String(s.tableName), Key: key("LINK", session.LinkID),
				UpdateExpression: aws.String("REMOVE activeSessionId"), ConditionExpression: aws.String("activeSessionId = :sessionId"),
				ExpressionAttributeValues: pointerValues,
			}})
		}
	}
	fenced := make(map[string]bool, len(fences))
	for _, endpointID := range []string{session.ControllerID, session.CompanionID} {
		if endpointID == "" || omit[itemKey("ENDPOINT", endpointID)] {
			continue
		}
		endpoint, err := s.GetEndpoint(ctx, endpointID)
		if err != nil {
			return false, err
		}
		if endpoint != nil && endpoint.ActiveSessionID == session.SessionID {
			condition := "activeSessionId = :sessionId"
			expressionValues := pointerValues
			if connectionID := fences[endpointID]; connectionID != "" {
				expressionValues, err = values(map[string]any{":sessionId": session.SessionID, ":connectionId": connectionID})
				if err != nil {
					return false, err
				}
				condition += " AND connectionId = :connectionId AND attribute_not_exists(revokedAt)"
				fenced[endpointID] = true
			}
			operations = append(operations, types.TransactWriteItem{Update: &types.Update{
				TableName: aws.String(s.tableName), Key: key("ENDPOINT", endpointID),
				UpdateExpression: aws.String("REMOVE activeSessionId"), ConditionExpression: aws.String(condition),
				ExpressionAttributeValues: expressionValues,
			}})
		}
	}
	for endpointID, connectionID := range fences {
		if connectionID == "" || fenced[endpointID] || omit[itemKey("ENDPOINT", endpointID)] {
			continue
		}
		fence, err := s.endpointFence(endpointID, connectionID)
		if err != nil {
			return false, err
		}
		operations = append(operations, fence)
	}
	if len(operations) == 0 {
		return false, nil
	}
	_, err = s.db.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{TransactItems: operations})
	return closing, err
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
