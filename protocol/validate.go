package protocol

import (
	"bytes"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	rendezvousSchemaID = "https://remote-davinci.dev/schemas/rendezvous-v1.schema.json"
	controlSchemaID    = "https://remote-davinci.dev/schemas/control-v1.schema.json"
	pairingSchemaID    = "https://remote-davinci.dev/schemas/pairing-v1.schema.json"
)

//go:embed schemas/*.json
var schemaFiles embed.FS

var validators = sync.OnceValue(compileSchemas)

type compiledSchemas struct {
	client, server, rendezvous, control, pairing, wormhole *jsonschema.Schema
}

func compileSchemas() compiledSchemas {
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	for name, id := range map[string]string{
		"rendezvous-v1.schema.json": rendezvousSchemaID,
		"control-v1.schema.json":    controlSchemaID,
		"pairing-v1.schema.json":    pairingSchemaID,
	} {
		data, err := schemaFiles.ReadFile("schemas/" + name)
		if err != nil {
			panic(err)
		}
		document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			panic(err)
		}
		if err := compiler.AddResource(id, document); err != nil {
			panic(err)
		}
	}
	return compiledSchemas{
		client:     compiler.MustCompile(rendezvousSchemaID + "#/$defs/clientEnvelope"),
		server:     compiler.MustCompile(rendezvousSchemaID + "#/$defs/serverEnvelope"),
		rendezvous: compiler.MustCompile(rendezvousSchemaID),
		control:    compiler.MustCompile(controlSchemaID),
		pairing:    compiler.MustCompile(pairingSchemaID),
		wormhole:   compiler.MustCompile(pairingSchemaID + "#/$defs/wormholeMessage"),
	}
}

func ParseClient(input any) (ClientEnvelope, error) {
	data, err := parse(input, validators().client, MaxWebSocketFrameBytes)
	if err != nil {
		return ClientEnvelope{}, err
	}
	var envelope ClientEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return ClientEnvelope{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	if err := rendezvousSemantics(envelope); err != nil {
		return ClientEnvelope{}, err
	}
	return envelope, nil
}

func ParseServer(input any) (ServerEnvelope, error) {
	data, err := parse(input, validators().server, MaxWebSocketFrameBytes)
	if err != nil {
		return ServerEnvelope{}, err
	}
	var envelope ServerEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return ServerEnvelope{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	if err := rendezvousSemantics(envelope); err != nil {
		return ServerEnvelope{}, err
	}
	return envelope, nil
}

func ParseRendezvous(input any) (RendezvousEnvelope, error) {
	data, err := parse(input, validators().rendezvous, MaxWebSocketFrameBytes)
	if err != nil {
		return RendezvousEnvelope{}, err
	}
	var envelope RendezvousEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return RendezvousEnvelope{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	if err := rendezvousSemantics(envelope); err != nil {
		return RendezvousEnvelope{}, err
	}
	return envelope, nil
}

func ParseControl(input any) (ControlEnvelope, error) {
	data, err := parse(input, validators().control, MaxControlPlaintextBytes)
	if err != nil {
		return ControlEnvelope{}, err
	}
	var envelope ControlEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return ControlEnvelope{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	if envelope.Type == "request" {
		var body ControlRequestBody
		if err := envelope.DecodeBody(&body); err != nil {
			return ControlEnvelope{}, validationError(InvalidMessage, "Protocol frame does not match the v1 contract")
		}
		if body.ExpiresAt < body.SentAt {
			return ControlEnvelope{}, validationError(InvalidMessage, "Request expiresAt must not precede sentAt")
		}
	}
	return envelope, nil
}

func ParsePairing(input any) (PairingIdentityEnvelope, error) {
	data, err := parse(input, validators().pairing, MaxPairingPlaintextBytes)
	if err != nil {
		return PairingIdentityEnvelope{}, err
	}
	var envelope PairingIdentityEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return PairingIdentityEnvelope{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	fingerprint, err := NoiseKeyFingerprint(envelope.Body.NoiseKey)
	if err != nil || fingerprint != envelope.Body.NoiseFingerprint {
		return PairingIdentityEnvelope{}, validationError(InvalidMessage, "Noise fingerprint does not match the public key")
	}
	return envelope, nil
}

func ParseWormhole(input any) (WormholeMessage, error) {
	data, err := parse(input, validators().wormhole, MaxRelayPayloadBytes)
	if err != nil {
		return WormholeMessage{}, err
	}
	var message WormholeMessage
	if err := json.Unmarshal(data, &message); err != nil {
		return WormholeMessage{}, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	body, err := hex.DecodeString(message.Body)
	if err != nil {
		return WormholeMessage{}, validationError(InvalidMessage, "Protocol frame does not match the v1 contract")
	}
	if message.Phase == "pake" {
		var wrapper struct {
			PakeV1 string `json:"pake_v1"`
		}
		if json.Unmarshal(body, &wrapper) != nil || wrapper.PakeV1 == "" {
			return WormholeMessage{}, validationError(InvalidMessage, "PAKE phase does not contain a valid pake_v1 wrapper")
		}
		decoded, decodeErr := hex.DecodeString(wrapper.PakeV1)
		if decodeErr != nil || len(decoded) == 0 || len(wrapper.PakeV1)%2 != 0 || strings.ToLower(wrapper.PakeV1) != wrapper.PakeV1 {
			return WormholeMessage{}, validationError(InvalidMessage, "PAKE phase does not contain a valid pake_v1 wrapper")
		}
	} else if len(body) < 40 {
		return WormholeMessage{}, validationError(InvalidMessage, "Encrypted Wormhole phases require a SecretBox nonce and tag")
	}
	return message, nil
}

func parse(input any, schema *jsonschema.Schema, maxBytes int) ([]byte, error) {
	data, err := inputJSON(input)
	if err != nil {
		return nil, validationError(InvalidMessage, "Protocol frame is not JSON-serializable")
	}
	if len(data) > maxBytes {
		return nil, validationError(PayloadTooLarge, "Protocol frame exceeds its byte limit")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return nil, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	if err := preflightFramePayload(value); err != nil {
		return nil, err
	}
	if err := schema.Validate(value); err != nil {
		if unsupportedVersion(value) {
			return nil, validationError(UnsupportedVersion, "Protocol version is not supported")
		}
		return nil, validationError(InvalidMessage, "Protocol frame does not match the v1 contract", schemaIssues(err)...)
	}
	value = normalizeIntegers(value)
	data, err = json.Marshal(value)
	if err != nil {
		return nil, validationError(InvalidMessage, "Protocol frame is not valid JSON")
	}
	return data, nil
}

func normalizeIntegers(value any) any {
	switch value := value.(type) {
	case map[string]any:
		for key, item := range value {
			value[key] = normalizeIntegers(item)
		}
	case []any:
		for index, item := range value {
			value[index] = normalizeIntegers(item)
		}
	case json.Number:
		number, ok := new(big.Rat).SetString(string(value))
		if ok && number.IsInt() && number.Num().IsInt64() {
			return number.Num().Int64()
		}
	}
	return value
}

func inputJSON(input any) ([]byte, error) {
	switch value := input.(type) {
	case string:
		return []byte(value), nil
	case []byte:
		return value, nil
	case json.RawMessage:
		return value, nil
	default:
		return json.Marshal(input)
	}
}

func unsupportedVersion(value any) bool {
	record, ok := value.(map[string]any)
	if !ok {
		return false
	}
	protocol, _ := record["protocol"].(string)
	version, exists := record["v"]
	if !exists || (protocol != ProtocolName && protocol != ControlProtocolName && protocol != PairingProtocolName) {
		return false
	}
	return fmt.Sprint(version) != "1"
}

func schemaIssues(err error) []string {
	var validation *jsonschema.ValidationError
	if !errors.As(err, &validation) {
		return nil
	}
	issues := make([]string, 0, len(validation.Causes))
	var visit func(*jsonschema.ValidationError)
	visit = func(current *jsonschema.ValidationError) {
		if len(current.Causes) == 0 {
			path := "/"
			if len(current.InstanceLocation) != 0 {
				path += strings.Join(current.InstanceLocation, "/")
			}
			issues = append(issues, path)
			return
		}
		for _, cause := range current.Causes {
			visit(cause)
		}
	}
	visit(validation)
	return issues
}

func preflightFramePayload(value any) error {
	record, ok := value.(map[string]any)
	if !ok || record["protocol"] != ProtocolName {
		return nil
	}
	messageType := record["type"]
	if messageType != "pair.frame" && messageType != "session.frame" {
		return nil
	}
	body, ok := record["body"].(map[string]any)
	if !ok {
		return nil
	}
	payload, ok := body["payload"].(string)
	if !ok {
		return nil
	}
	decoded, canonical := canonicalBase64URL(payload)
	if !canonical {
		return validationError(InvalidMessage, "Relay payload must be canonical unpadded base64url")
	}
	if len(decoded) > MaxRelayPayloadBytes {
		return validationError(PayloadTooLarge, "Decoded relay payload exceeds 16 KiB")
	}
	return nil
}

func rendezvousSemantics(envelope Envelope) error {
	if envelope.Type == "pair.commit" {
		var body PairCommitBody
		if err := envelope.DecodeBody(&body); err != nil {
			return validationError(InvalidMessage, "Protocol frame does not match the v1 contract")
		}
		if body.Self.EndpointID == body.Peer.EndpointID || body.Self.Role == body.Peer.Role {
			return validationError(InvalidMessage, "Pairing endpoints must be distinct and have opposite roles")
		}
	}
	return nil
}
