package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/anhydrous99/remote-davinci/services/rendezvous-relay/internal/relay"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
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
	lambda.Start(relay.NewAuthorizer(store))
}
