package relay

import "github.com/anhydrous99/remote-davinci/protocol"

type Connection struct {
	ConnectionID string `dynamodbav:"connectionId"`
	AuthMode     string `dynamodbav:"authMode"`
	EndpointID   string `dynamodbav:"endpointId,omitempty"`
	SourceKey    string `dynamodbav:"sourceKey"`
	PairingID    string `dynamodbav:"pairingId,omitempty"`
	ConnectedAt  int64  `dynamodbav:"connectedAt"`
	ExpiresAt    int64  `dynamodbav:"expiresAt"`
}

type Endpoint struct {
	EndpointID      string              `dynamodbav:"endpointId"`
	CredentialHash  string              `dynamodbav:"credentialHash"`
	Role            protocol.DeviceRole `dynamodbav:"role"`
	ConnectionID    string              `dynamodbav:"connectionId,omitempty"`
	ActiveSessionID string              `dynamodbav:"activeSessionId,omitempty"`
	RevokedAt       int64               `dynamodbav:"revokedAt,omitempty"`
	CreatedAt       int64               `dynamodbav:"createdAt"`
	UpdatedAt       int64               `dynamodbav:"updatedAt"`
}

type PairSide struct {
	ConnectionID string `dynamodbav:"connectionId"`
	SideID       string `dynamodbav:"sideId"`
}

type PairIdentity struct {
	EndpointID string              `dynamodbav:"endpointId"`
	Role       protocol.DeviceRole `dynamodbav:"role"`
}

type PairEndpointCommit struct {
	EndpointID     string              `dynamodbav:"endpointId"`
	Role           protocol.DeviceRole `dynamodbav:"role"`
	CredentialHash string              `dynamodbav:"credentialHash"`
}

type PairCommit struct {
	ConnectionID string             `dynamodbav:"connectionId"`
	SideID       string             `dynamodbav:"sideId"`
	LinkID       string             `dynamodbav:"linkId"`
	Self         PairEndpointCommit `dynamodbav:"self"`
	Peer         PairIdentity       `dynamodbav:"peer"`
}

type Pair struct {
	PairID        string      `dynamodbav:"pairId"`
	Locator       string      `dynamodbav:"locator,omitempty"`
	JoinTokenHash string      `dynamodbav:"joinTokenHash,omitempty"`
	Status        string      `dynamodbav:"status"`
	SideA         PairSide    `dynamodbav:"sideA"`
	SideB         *PairSide   `dynamodbav:"sideB,omitempty"`
	CommitA       *PairCommit `dynamodbav:"commitA,omitempty"`
	CommitB       *PairCommit `dynamodbav:"commitB,omitempty"`
	ExpiresAt     int64       `dynamodbav:"expiresAt"`
}

type Link struct {
	LinkID          string `dynamodbav:"linkId"`
	ControllerID    string `dynamodbav:"controllerId"`
	CompanionID     string `dynamodbav:"companionId"`
	Status          string `dynamodbav:"status"`
	ActiveSessionID string `dynamodbav:"activeSessionId,omitempty"`
	CreatedAt       int64  `dynamodbav:"createdAt"`
	RevokedAt       int64  `dynamodbav:"revokedAt,omitempty"`
}

type Session struct {
	SessionID              string `dynamodbav:"sessionId"`
	LinkID                 string `dynamodbav:"linkId"`
	ControllerID           string `dynamodbav:"controllerId"`
	CompanionID            string `dynamodbav:"companionId"`
	ControllerConnectionID string `dynamodbav:"controllerConnectionId"`
	CompanionConnectionID  string `dynamodbav:"companionConnectionId"`
	Status                 string `dynamodbav:"status"`
	CreatedAt              int64  `dynamodbav:"createdAt"`
	ExpiresAt              int64  `dynamodbav:"expiresAt"`
	ClosedAt               int64  `dynamodbav:"closedAt,omitempty"`
}

type CloseSessionResult struct {
	Session   Session
	ClosedNow bool
}

type DisconnectResult struct {
	Connection Connection
	Session    *CloseSessionResult
}

type RevokeLinkResult struct {
	Link    Link
	Session *CloseSessionResult
}

type RevokeEndpointResult struct {
	Endpoint Endpoint
	Session  *CloseSessionResult
}

type CommitPairResult struct {
	Pair         Pair
	Link         *Link
	ActivatedNow bool
}

type ServiceError struct {
	Code         protocol.ErrorCode
	Retryable    bool
	RetryAfterMS *int64
}

func (e *ServiceError) Error() string { return string(e.Code) }

func serviceError(code protocol.ErrorCode) *ServiceError { return &ServiceError{Code: code} }

func retryableError(code protocol.ErrorCode) *ServiceError {
	return &ServiceError{Code: code, Retryable: true}
}

func SameCommit(a, b PairCommit) bool { return a == b }

func ReciprocalCommits(a, b PairCommit) bool {
	return a.LinkID == b.LinkID &&
		a.Self.EndpointID != a.Peer.EndpointID &&
		a.Self.EndpointID == b.Peer.EndpointID &&
		a.Peer.EndpointID == b.Self.EndpointID &&
		a.Self.Role == b.Peer.Role &&
		a.Peer.Role == b.Self.Role &&
		a.Self.Role != a.Peer.Role
}

func LinkFromCommits(a, b PairCommit, now int64) (Link, error) {
	if !ReciprocalCommits(a, b) {
		return Link{}, serviceError(protocol.Conflict)
	}
	controller, companion := a.Self, b.Self
	if b.Self.Role == protocol.Controller {
		controller, companion = b.Self, a.Self
	}
	return Link{
		LinkID: a.LinkID, ControllerID: controller.EndpointID, CompanionID: companion.EndpointID,
		Status: "ACTIVE", CreatedAt: now,
	}, nil
}
