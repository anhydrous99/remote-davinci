package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

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
	configuration, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		slog.Error("load AWS configuration", "error", err)
		os.Exit(1)
	}
	store := relay.NewDynamoStore(tableName, dynamodb.NewFromConfig(configuration))
	management := apigatewaymanagementapi.NewFromConfig(configuration)
	post := func(ctx context.Context, connectionID string, message relay.Message, event relay.WebSocketEvent) error {
		if event.RequestContext.DomainName == "" || event.RequestContext.Stage == "" {
			return errors.New("missing WebSocket management endpoint")
		}
		data, err := relay.MarshalMessage(message)
		if err != nil {
			return err
		}
		_, err = management.PostToConnection(ctx, &apigatewaymanagementapi.PostToConnectionInput{
			ConnectionId: aws.String(connectionID), Data: data,
		}, func(options *apigatewaymanagementapi.Options) {
			options.BaseEndpoint = aws.String("https://" + event.RequestContext.DomainName + "/" + event.RequestContext.Stage)
		})
		return err
	}
	lambda.Start(relay.NewHandler(relay.HandlerDependencies{Store: store, Post: post}).Handle)
}
