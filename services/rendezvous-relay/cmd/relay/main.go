package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"

	"github.com/anhydrous99/remote-davinci/services/rendezvous-relay/internal/relay"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/apigatewaymanagementapi"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	tableName := os.Getenv("TABLE_NAME")
	if tableName == "" {
		slog.Error("TABLE_NAME is required")
		os.Exit(1)
	}
	pairActivationLimit, err := pairActivationsPerSourceHour()
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
	configuration, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		slog.Error("load AWS configuration", "error", err)
		os.Exit(1)
	}
	store := relay.NewDynamoStore(tableName, dynamodb.NewFromConfig(configuration), pairActivationLimit)
	management := apigatewaymanagementapi.NewFromConfig(configuration)
	managementEndpoint := func(event relay.WebSocketEvent) (string, error) {
		if event.RequestContext.DomainName == "" || event.RequestContext.Stage == "" {
			return "", errors.New("missing WebSocket management endpoint")
		}
		return "https://" + event.RequestContext.DomainName + "/" + event.RequestContext.Stage, nil
	}
	post := func(ctx context.Context, connectionID string, message relay.Message, event relay.WebSocketEvent) error {
		endpoint, err := managementEndpoint(event)
		if err != nil {
			return err
		}
		data, err := relay.MarshalMessage(message)
		if err != nil {
			return err
		}
		_, err = management.PostToConnection(ctx, &apigatewaymanagementapi.PostToConnectionInput{
			ConnectionId: aws.String(connectionID), Data: data,
		}, func(options *apigatewaymanagementapi.Options) {
			options.BaseEndpoint = aws.String(endpoint)
		})
		return err
	}
	drop := func(ctx context.Context, connectionID string, event relay.WebSocketEvent) error {
		endpoint, err := managementEndpoint(event)
		if err != nil {
			return err
		}
		_, err = management.DeleteConnection(ctx, &apigatewaymanagementapi.DeleteConnectionInput{
			ConnectionId: aws.String(connectionID),
		}, func(options *apigatewaymanagementapi.Options) {
			options.BaseEndpoint = aws.String(endpoint)
		})
		return err
	}
	lambda.Start(relay.NewHandler(relay.HandlerDependencies{Store: store, Post: post, Drop: drop}).Handle)
}

func pairActivationsPerSourceHour() (int64, error) {
	const name = "PAIR_ACTIVATIONS_PER_SOURCE_PER_HOUR"
	raw := os.Getenv(name)
	if raw == "" {
		return 10, nil
	}
	limit, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || limit < 1 || limit > 10_000 {
		return 0, errors.New(name + " must be an integer from 1 through 10000")
	}
	return limit, nil
}
