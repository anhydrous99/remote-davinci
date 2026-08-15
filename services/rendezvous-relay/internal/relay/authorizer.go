package relay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/anhydrous99/remote-davinci/protocol"
)

type AuthorizerEvent struct {
	Headers   map[string]string `json:"headers"`
	MethodARN string            `json:"methodArn"`
	RouteARN  string            `json:"routeArn"`
}

type AuthorizerResult struct {
	PrincipalID    string                   `json:"principalId"`
	PolicyDocument AuthorizerPolicyDocument `json:"policyDocument"`
	Context        map[string]any           `json:"context"`
}

type AuthorizerPolicyDocument struct {
	Version   string                      `json:"Version"`
	Statement []AuthorizerPolicyStatement `json:"Statement"`
}

type AuthorizerPolicyStatement struct {
	Action   string `json:"Action"`
	Effect   string `json:"Effect"`
	Resource string `json:"Resource"`
}

type endpointReader interface {
	GetEndpoint(context.Context, string) (*Endpoint, error)
}

var errUnauthorized = errors.New("Unauthorized")

func NewAuthorizer(store endpointReader) func(context.Context, AuthorizerEvent) (AuthorizerResult, error) {
	return func(ctx context.Context, event AuthorizerEvent) (AuthorizerResult, error) {
		header := ""
		for name, value := range event.Headers {
			if strings.EqualFold(name, "authorization") {
				header = value
				break
			}
		}
		authorization, err := protocol.ParseAuthorization(header)
		if err != nil {
			return AuthorizerResult{}, errUnauthorized
		}
		contextValues := map[string]any{"authMode": "pairing"}
		principalID := "pairing"
		if authorization.Scheme == "bearer" {
			endpoint, err := store.GetEndpoint(ctx, authorization.EndpointID)
			if err != nil {
				return AuthorizerResult{}, err
			}
			hash := credentialDigest(authorization.Secret)
			if endpoint == nil || endpoint.RevokedAt != 0 || !constantTimeEqual(endpoint.CredentialHash, hash) {
				return AuthorizerResult{}, errUnauthorized
			}
			principalID = authorization.EndpointID
			contextValues = map[string]any{
				"authMode": "endpoint", "endpointId": authorization.EndpointID, "credentialHash": hash,
			}
		}
		resource := event.MethodARN
		if resource == "" {
			resource = event.RouteARN
		}
		if resource == "" {
			return AuthorizerResult{}, errUnauthorized
		}
		return AuthorizerResult{
			PrincipalID: principalID,
			PolicyDocument: AuthorizerPolicyDocument{
				Version:   "2012-10-17",
				Statement: []AuthorizerPolicyStatement{{Action: "execute-api:Invoke", Effect: "Allow", Resource: resource}},
			},
			Context: contextValues,
		}, nil
	}
}

func credentialDigest(secret string) string {
	decoded, _ := base64.RawURLEncoding.DecodeString(secret)
	digest := sha256.Sum256(decoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
