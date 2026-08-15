import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  type StackProps,
} from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import type { Construct } from 'constructs';

export interface RendezvousRelayStackProps extends StackProps {
  readonly environment: 'dev' | 'prod';
}

export class RendezvousRelayStack extends Stack {
  constructor(scope: Construct, id: string, props: RendezvousRelayStackProps) {
    super(scope, id, props);

    const production = props.environment === 'prod';
    const removalPolicy = production ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;
    const repositoryRoot = path.join(__dirname, '../../../..');
    const goCode = (name: string, command: string): lambda.Code => {
      const output = path.join(repositoryRoot, '.build', name);
      fs.mkdirSync(output, { recursive: true });
      return lambda.Code.fromCustomCommand(
        output,
        [
          'go',
          'build',
          '-trimpath',
          '-tags',
          'lambda.norpc',
          '-ldflags=-s -w',
          '-o',
          path.join(output, 'bootstrap'),
          command,
        ],
        {
          commandOptions: {
            cwd: repositoryRoot,
            env: {
              ...process.env,
              CGO_ENABLED: '0',
              GOARCH: 'arm64',
              GOOS: 'linux',
            },
          },
        },
      );
    };

    const table = new dynamodb.Table(this, 'State', {
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      deletionProtection: production,
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: production,
      },
      removalPolicy,
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: 'expiresAt',
    });

    const lambdaDefaults = {
      architecture: lambda.Architecture.ARM_64,
      environment: { TABLE_NAME: table.tableName },
      loggingFormat: lambda.LoggingFormat.JSON,
      memorySize: 256,
      runtime: lambda.Runtime.PROVIDED_AL2023,
      timeout: Duration.seconds(10),
    } as const;
    const lambdaLogProps = {
      removalPolicy,
      retention: production
        ? logs.RetentionDays.THREE_MONTHS
        : logs.RetentionDays.ONE_WEEK,
    } as const;

    const authorizerHandler = new lambda.Function(this, 'AuthorizerHandler', {
      ...lambdaDefaults,
      code: goCode('authorizer', './services/rendezvous-relay/cmd/authorizer'),
      handler: 'bootstrap',
      logGroup: new logs.LogGroup(this, 'AuthorizerLogs', lambdaLogProps),
    });
    const relayHandler = new lambda.Function(this, 'RelayHandler', {
      ...lambdaDefaults,
      code: goCode('relay', './services/rendezvous-relay/cmd/relay'),
      handler: 'bootstrap',
      logGroup: new logs.LogGroup(this, 'RelayLogs', lambdaLogProps),
    });

    table.grant(authorizerHandler, 'dynamodb:GetItem');
    table.grant(
      relayHandler,
      'dynamodb:DeleteItem',
      'dynamodb:GetItem',
      'dynamodb:PutItem',
      'dynamodb:Query',
      'dynamodb:TransactWriteItems',
      'dynamodb:UpdateItem',
    );

    const authorizer = new authorizers.WebSocketLambdaAuthorizer(
      'ConnectAuthorizer',
      authorizerHandler,
      { identitySource: ['route.request.header.Authorization'] },
    );
    const api = new apigwv2.WebSocketApi(this, 'Api', {
      connectRouteOptions: {
        authorizer,
        integration: new integrations.WebSocketLambdaIntegration(
          'ConnectIntegration',
          relayHandler,
        ),
      },
      defaultRouteOptions: {
        integration: new integrations.WebSocketLambdaIntegration(
          'DefaultIntegration',
          relayHandler,
        ),
      },
      disconnectRouteOptions: {
        integration: new integrations.WebSocketLambdaIntegration(
          'DisconnectIntegration',
          relayHandler,
        ),
      },
      routeSelectionExpression: '$request.body.type',
    });

    const accessLogs = new logs.LogGroup(this, 'AccessLogs', {
      removalPolicy,
      retention: production
        ? logs.RetentionDays.THREE_MONTHS
        : logs.RetentionDays.ONE_WEEK,
    });
    accessLogs.grantWrite(new iam.ServicePrincipal('apigateway.amazonaws.com'));

    const stage = new apigwv2.WebSocketStage(this, 'Stage', {
      autoDeploy: true,
      stageName: 'v1',
      webSocketApi: api,
    });
    const cfnStage = stage.node.defaultChild as apigwv2.CfnStage;
    cfnStage.accessLogSettings = {
      destinationArn: accessLogs.logGroupArn,
      format: JSON.stringify({
        apiId: '$context.apiId',
        connectionId: '$context.connectionId',
        error: '$context.error.message',
        requestId: '$context.requestId',
        routeKey: '$context.routeKey',
        status: '$context.status',
      }),
    };
    cfnStage.defaultRouteSettings = {
      dataTraceEnabled: false,
      detailedMetricsEnabled: true,
      throttlingBurstLimit: 100,
      throttlingRateLimit: 50,
    };

    relayHandler.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['execute-api:ManageConnections'],
        resources: [
          this.formatArn({
            service: 'execute-api',
            resource: api.apiId,
            resourceName: `${stage.stageName}/POST/@connections/*`,
          }),
        ],
      }),
    );

    for (const [name, fn] of [
      ['Authorizer', authorizerHandler],
      ['Relay', relayHandler],
    ] as const) {
      new cloudwatch.Alarm(this, `${name}Errors`, {
        alarmDescription: `${name} Lambda reported an error`,
        evaluationPeriods: 1,
        metric: fn.metricErrors({ period: Duration.minutes(5) }),
        threshold: 1,
      });
      new cloudwatch.Alarm(this, `${name}Throttles`, {
        alarmDescription: `${name} Lambda was throttled`,
        evaluationPeriods: 1,
        metric: fn.metricThrottles({ period: Duration.minutes(5) }),
        threshold: 1,
      });
    }

    new cloudwatch.Alarm(this, 'ApiServerErrors', {
      alarmDescription: 'WebSocket API returned a 5xx response',
      evaluationPeriods: 1,
      metric: new cloudwatch.Metric({
        dimensionsMap: { ApiId: api.apiId, Stage: stage.stageName },
        metricName: '5XXError',
        namespace: 'AWS/ApiGateway',
        period: Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 1,
    });
    new cloudwatch.Alarm(this, 'TableThrottles', {
      alarmDescription: 'DynamoDB throttled a rendezvous operation',
      evaluationPeriods: 1,
      metric: table.metricThrottledRequestsForOperations({
        operations: [
          dynamodb.Operation.DELETE_ITEM,
          dynamodb.Operation.GET_ITEM,
          dynamodb.Operation.PUT_ITEM,
          dynamodb.Operation.QUERY,
          dynamodb.Operation.TRANSACT_WRITE_ITEMS,
          dynamodb.Operation.UPDATE_ITEM,
        ],
        period: Duration.minutes(5),
      }),
      threshold: 1,
    });

    new CfnOutput(this, 'WebSocketUrl', { value: stage.url });
  }
}
