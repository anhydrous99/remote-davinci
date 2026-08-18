import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  Tags,
  type StackProps,
} from 'aws-cdk-lib';
import * as apigwv2 from 'aws-cdk-lib/aws-apigatewayv2';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cloudwatchActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as sns from 'aws-cdk-lib/aws-sns';
import type { Construct } from 'constructs';

export interface RendezvousRelayStackProps extends StackProps {
  readonly environment: 'dev' | 'prod';
  readonly accessLogs?: boolean;
  readonly alarmTopicArn?: string;
}

export class RendezvousRelayStack extends Stack {
  constructor(scope: Construct, id: string, props: RendezvousRelayStackProps) {
    super(scope, id, props);

    const production = props.environment === 'prod';
    const accessLogging = props.accessLogs ?? true;
    const relayRejectionsNamespace = `RemoteDavinci/${props.environment}`;
    const removalPolicy = production ? RemovalPolicy.RETAIN : RemovalPolicy.DESTROY;
    const alarmTopicArn = props.alarmTopicArn;
    if (production && alarmTopicArn === undefined) {
      throw new Error('Production requires an existing SNS alarm topic ARN');
    }
    if (alarmTopicArn !== undefined) {
      const match = /^arn:[^:]+:sns:([^:]+):(\d{12}):[^:]+$/.exec(alarmTopicArn);
      if (match === null) {
        throw new Error('alarmTopicArn must be an SNS topic ARN');
      }
      if (production && (match[1] !== this.region || match[2] !== this.account)) {
        throw new Error('Production alarmTopicArn must match the deployment account and region');
      }
    }
    Tags.of(this).add('Project', 'remote-davinci');
    Tags.of(this).add('Environment', props.environment);
    const repositoryRoot = path.join(__dirname, '../../../..');
    const goCode = (name: string, command: string): lambda.Code => {
      const output = path.join(repositoryRoot, '.build', name);
      fs.rmSync(output, { force: true, recursive: true });
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
      ...(production
        ? {
            maxReadRequestUnits: 30_000,
            maxWriteRequestUnits: 8_000,
          }
        : {}),
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
      ...(production
        ? {
            applicationLogLevelV2: lambda.ApplicationLogLevel.WARN,
            systemLogLevelV2: lambda.SystemLogLevel.WARN,
          }
        : {}),
      runtime: lambda.Runtime.PROVIDED_AL2023,
      timeout: Duration.seconds(10),
    } as const;
    const lambdaLogProps = {
      removalPolicy,
      retention: production
        ? logs.RetentionDays.ONE_MONTH
        : logs.RetentionDays.THREE_DAYS,
    } as const;

    const relayLogs = new logs.LogGroup(this, 'RelayLogs', lambdaLogProps);
    const relayRole = new iam.Role(this, 'RelayRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    relayLogs.grantWrite(relayRole);
    const relayHandler = new lambda.Function(this, 'RelayHandler', {
      ...lambdaDefaults,
      code: goCode('relay', './services/rendezvous-relay/cmd/relay'),
      handler: 'bootstrap',
      logGroup: relayLogs,
      role: relayRole,
    });

    new logs.MetricFilter(this, 'RelayRejectionsMetric', {
      defaultValue: 0,
      filterPattern: logs.FilterPattern.anyTerm(
        'connect-rejected',
        'message-rejected',
        'RATE_LIMITED',
      ),
      logGroup: relayLogs,
      metricName: 'RelayRejections',
      metricNamespace: relayRejectionsNamespace,
      metricValue: '1',
    });

    table.grant(
      relayHandler,
      'dynamodb:DeleteItem',
      'dynamodb:GetItem',
      'dynamodb:PutItem',
      'dynamodb:UpdateItem',
    );

    const api = new apigwv2.WebSocketApi(this, 'Api', {
      connectRouteOptions: {
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
        returnResponse: true,
      },
      disconnectRouteOptions: {
        integration: new integrations.WebSocketLambdaIntegration(
          'DisconnectIntegration',
          relayHandler,
        ),
      },
      routeSelectionExpression: '$request.body.type',
    });
    for (const route of ['pair.frame', 'session.frame']) {
      api.addRoute(route, {
        integration: new integrations.WebSocketLambdaIntegration(
          `${route}Integration`,
          relayHandler,
        ),
      });
    }

    const stage = new apigwv2.WebSocketStage(this, 'Stage', {
      autoDeploy: true,
      stageName: 'v1',
      webSocketApi: api,
    });
    const cfnStage = stage.node.defaultChild as apigwv2.CfnStage;
    for (const route of api.node.findAll()) {
      if (route instanceof apigwv2.CfnRoute) {
        cfnStage.addResourceDependency(route);
      }
    }
    if (accessLogging) {
      const accessLogs = new logs.LogGroup(this, 'AccessLogs', {
        removalPolicy,
        retention: production
          ? logs.RetentionDays.ONE_WEEK
          : logs.RetentionDays.THREE_DAYS,
      });
      accessLogs.grantWrite(new iam.ServicePrincipal('apigateway.amazonaws.com'));
      cfnStage.accessLogSettings = {
        destinationArn: accessLogs.logGroupArn,
        format: JSON.stringify({
          error: '$context.error.message',
          requestId: '$context.requestId',
          routeKey: '$context.routeKey',
          status: '$context.status',
        }),
      };
    }
    cfnStage.defaultRouteSettings = {
      dataTraceEnabled: false,
      detailedMetricsEnabled: false,
    };
    // CDK passes the untyped route-settings map through without normalizing keys.
    const routeSettings = (rate: number, burst: number) => ({
      DataTraceEnabled: false,
      DetailedMetricsEnabled: false,
      ThrottlingBurstLimit: burst,
      ThrottlingRateLimit: rate,
    });
    cfnStage.routeSettings = {
      '$connect': routeSettings(production ? 400 : 50, production ? 500 : 100),
      '$default': routeSettings(production ? 500 : 50, production ? 1_000 : 100),
      '$disconnect': routeSettings(production ? 500 : 50, production ? 1_000 : 100),
      'pair.frame': routeSettings(production ? 500 : 50, production ? 1_000 : 100),
      'session.frame': routeSettings(
        production ? 4_000 : 50,
        production ? 5_000 : 100,
      ),
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

    const alarms = [
      new cloudwatch.Alarm(this, 'RelayErrors', {
        alarmDescription: 'Relay Lambda reported an error',
        evaluationPeriods: 1,
        metric: relayHandler.metricErrors({ period: Duration.minutes(5) }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, 'RelayThrottles', {
        alarmDescription: 'Relay Lambda was throttled',
        evaluationPeriods: 1,
        metric: relayHandler.metricThrottles({ period: Duration.minutes(5) }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, 'RelayRejections', {
        alarmDescription: 'Relay rejected or rate-limited connections or messages',
        evaluationPeriods: 1,
        metric: new cloudwatch.Metric({
          metricName: 'RelayRejections',
          namespace: relayRejectionsNamespace,
          period: Duration.minutes(5),
          statistic: 'Sum',
        }),
        threshold: 20,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, 'ApiExecutionErrors', {
        alarmDescription: 'WebSocket API failed to execute an integration',
        evaluationPeriods: 1,
        metric: new cloudwatch.Metric({
          dimensionsMap: { ApiId: api.apiId, Stage: stage.stageName },
          metricName: 'ExecutionError',
          namespace: 'AWS/ApiGateway',
          period: Duration.minutes(5),
          statistic: 'Sum',
        }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, 'TableThrottles', {
        alarmDescription: 'DynamoDB throttled a rendezvous operation',
        evaluationPeriods: 1,
        metric: table.metricThrottledRequestsForOperations({
          operations: [
            dynamodb.Operation.GET_ITEM,
            dynamodb.Operation.TRANSACT_WRITE_ITEMS,
            dynamodb.Operation.UPDATE_ITEM,
          ],
          period: Duration.minutes(5),
        }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ];
    if (alarmTopicArn !== undefined) {
      const action = new cloudwatchActions.SnsAction(
        sns.Topic.fromTopicArn(this, 'AlarmTopic', alarmTopicArn),
      );
      for (const alarm of alarms) {
        alarm.addAlarmAction(action);
      }
    }

    new CfnOutput(this, 'WebSocketUrl', { value: stage.url });
  }
}
