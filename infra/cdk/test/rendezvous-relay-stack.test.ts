import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { describe, it } from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { deploymentConfig } from '../bin/remote-davinci.js';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

const testAccount = '111111111111';
const testRegion = 'us-east-1';
const testAlarmTopicArn = `arn:aws:sns:${testRegion}:${testAccount}:remote-davinci-alerts`;

function template(
  environment: 'dev' | 'prod' = 'dev',
  accessLogs?: boolean,
): Template {
  const app = new App();
  return Template.fromStack(
    new RendezvousRelayStack(app, `Test-${environment}`, {
      ...(accessLogs === undefined ? {} : { accessLogs }),
      ...(environment === 'prod' ? { alarmTopicArn: testAlarmTopicArn } : {}),
      environment,
      env: { account: testAccount, region: testRegion },
    }),
  );
}

describe('RendezvousRelayStack', () => {
  it('contains only the requested serverless boundary', () => {
    const stack = template();

    stack.resourceCountIs('AWS::DynamoDB::Table', 1);
    stack.resourceCountIs('AWS::IAM::Role', 1);
    stack.resourceCountIs('AWS::Lambda::Function', 1);
    stack.resourceCountIs('AWS::Logs::LogGroup', 2);
    stack.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    stack.resourceCountIs('AWS::ApiGatewayV2::Authorizer', 0);
    stack.resourceCountIs('AWS::ApiGatewayV2::Route', 5);
    stack.resourceCountIs('AWS::ApiGatewayV2::RouteResponse', 1);
    stack.resourceCountIs('AWS::CloudWatch::Alarm', 5);
    stack.resourceCountIs('AWS::Logs::MetricFilter', 1);
    stack.resourceCountIs('AWS::SQS::Queue', 0);
    stack.resourceCountIs('AWS::EC2::VPC', 0);
    stack.resourceCountIs('AWS::Cognito::UserPool', 0);

    const resources = stack.toJSON().Resources as Record<
      string,
      { DependsOn?: string[]; Type: string }
    >;
    const routeIds = Object.entries(resources)
      .filter(([, resource]) => resource.Type === 'AWS::ApiGatewayV2::Route')
      .map(([id]) => id);
    const renderedStage = Object.values(resources).find(
      (resource) => resource.Type === 'AWS::ApiGatewayV2::Stage',
    );
    assert.ok(renderedStage);
    for (const routeId of routeIds) {
      assert.ok(renderedStage.DependsOn?.includes(routeId));
    }

    stack.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
      KeySchema: [
        { AttributeName: 'pk', KeyType: 'HASH' },
        { AttributeName: 'sk', KeyType: 'RANGE' },
      ],
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: false },
      SSESpecification: { SSEEnabled: true },
      TimeToLiveSpecification: { AttributeName: 'expiresAt', Enabled: true },
    });
    for (const routeKey of [
      '$connect',
      '$disconnect',
      '$default',
      'pair.frame',
      'session.frame',
    ]) {
      stack.hasResourceProperties('AWS::ApiGatewayV2::Route', { RouteKey: routeKey });
    }
    stack.hasResourceProperties('AWS::ApiGatewayV2::Route', {
      AuthorizationType: 'NONE',
      RouteKey: '$connect',
    });
    stack.hasResourceProperties('AWS::ApiGatewayV2::Route', {
      RouteKey: '$default',
      RouteResponseSelectionExpression: '$default',
    });
    stack.hasResourceProperties('AWS::ApiGatewayV2::RouteResponse', {
      RouteResponseKey: '$default',
    });
    stack.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
      DefaultRouteSettings: {
        DataTraceEnabled: false,
        DetailedMetricsEnabled: false,
      },
      RouteSettings: {
        '$connect': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        '$default': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        '$disconnect': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        'pair.frame': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
        'session.frame': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 100,
          ThrottlingRateLimit: 50,
        },
      },
      StageName: 'v1',
    });
    stack.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmDescription: 'WebSocket API failed to execute an integration',
      MetricName: 'ExecutionError',
      Namespace: 'AWS/ApiGateway',
    });
    for (const alarm of Object.values(
      stack.findResources('AWS::CloudWatch::Alarm'),
    )) {
      assert.equal(alarm.Properties.TreatMissingData, 'notBreaching');
      assert.equal(alarm.Properties.AlarmActions, undefined);
    }
    stack.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmDescription: 'Relay rejected or rate-limited connections or messages',
      MetricName: 'RelayRejections',
      Namespace: 'RemoteDavinci/dev',
      Threshold: 20,
    });
    const metricFilters = Object.values(
      stack.findResources('AWS::Logs::MetricFilter'),
    );
    assert.equal(metricFilters.length, 1);
    assert.match(metricFilters[0]?.Properties.FilterPattern, /connect-rejected/);
    assert.match(metricFilters[0]?.Properties.FilterPattern, /message-rejected/);
    assert.match(metricFilters[0]?.Properties.FilterPattern, /RATE_LIMITED/);
    assert.deepEqual(metricFilters[0]?.Properties.MetricTransformations, [
      {
        DefaultValue: 0,
        MetricName: 'RelayRejections',
        MetricNamespace: 'RemoteDavinci/dev',
        MetricValue: '1',
      },
    ]);
    stack.hasResourceProperties('AWS::CloudWatch::Alarm', {
      AlarmDescription: 'DynamoDB throttled a rendezvous operation',
      Metrics: Match.arrayWith([
        Match.objectLike({
          MetricStat: {
            Metric: {
              Dimensions: Match.arrayWith([
                { Name: 'Operation', Value: 'GetItem' },
              ]),
              MetricName: 'ThrottledRequests',
              Namespace: 'AWS/DynamoDB',
            },
          },
        }),
      ]),
    });
    stack.hasOutput('WebSocketUrl', { Value: Match.anyValue() });
    const functions = Object.values(stack.findResources('AWS::Lambda::Function'));
    assert.equal(functions.length, 1);
    assert.deepEqual(functions[0]?.Properties.Architectures, ['arm64']);
    assert.equal(functions[0]?.Properties.Handler, 'bootstrap');
    assert.equal(functions[0]?.Properties.Runtime, 'provided.al2023');
    assert.equal(functions[0]?.Properties.ReservedConcurrentExecutions, undefined);
    for (const log of Object.values(
      stack.findResources('AWS::Logs::LogGroup'),
    )) {
      assert.equal(log.Properties.RetentionInDays, 3);
    }
  });

  it('builds an executable Linux ARM64 relay bootstrap asset', () => {
    const assetDirectory = path.join(__dirname, '../../../../.build/relay');
    const staleFile = path.join(assetDirectory, 'stale');
    fs.mkdirSync(assetDirectory, { recursive: true });
    fs.writeFileSync(staleFile, 'must not enter the Lambda asset');
    template();
    assert.equal(fs.existsSync(staleFile), false);
    const bootstrap = path.join(assetDirectory, 'bootstrap');
    const bytes = fs.readFileSync(bootstrap);
    assert.deepEqual([...bytes.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46]);
    assert.equal(bytes.readUInt16LE(18), 183);
    assert.notEqual(fs.statSync(bootstrap).mode & 0o111, 0);
  });

  it('preserves the remaining baseline logical IDs', () => {
    const ids = Object.keys(template().toJSON().Resources);
    for (const id of [
      'ApiF70053CD',
      'RelayHandler744E9E85',
      'RelayLogs019433A2',
      'Stage0E8C2AF5',
      'State1C20CC9A',
    ]) {
      assert.ok(ids.includes(id), `missing baseline logical ID ${id}`);
    }
    assert.equal(ids.some((id) => id.includes('Authorizer')), false);
  });

  it('scopes runtime permissions without query access', () => {
    const json = template().toJSON();
    const policies = Object.values(json.Resources).filter(
      (resource): resource is Record<string, unknown> =>
        (resource as { Type?: string }).Type === 'AWS::IAM::Policy',
    );
    const rendered = JSON.stringify(policies);

    assert.match(rendered, /execute-api:ManageConnections/);
    assert.match(rendered, /dynamodb:DeleteItem/);
    assert.match(rendered, /dynamodb:GetItem/);
    assert.match(rendered, /dynamodb:PutItem/);
    assert.match(rendered, /dynamodb:UpdateItem/);
    assert.match(rendered, /logs:CreateLogStream/);
    assert.match(rendered, /logs:PutLogEvents/);
    assert.match(rendered, /RelayLogs/);
    assert.doesNotMatch(rendered, /"Resource":"\*"/);
    assert.doesNotMatch(rendered, /dynamodb:TransactWriteItems/);
    assert.doesNotMatch(rendered, /dynamodb:Query/);
    assert.doesNotMatch(rendered, /dynamodb:Scan/);
    assert.doesNotMatch(JSON.stringify(json.Resources), /ApiGatewayV2::Authorizer/);
    assert.doesNotMatch(JSON.stringify(json.Resources), /AuthorizationType.*CUSTOM/);
    assert.doesNotMatch(
      JSON.stringify(json.Resources),
      /AWSLambdaBasicExecutionRole/,
    );
    const tableAlarm = Object.values(json.Resources).find(
      (resource) =>
        (resource as { Properties?: { AlarmDescription?: string } }).Properties
          ?.AlarmDescription === 'DynamoDB throttled a rendezvous operation',
    );
    assert.ok(tableAlarm);
    assert.doesNotMatch(JSON.stringify(tableAlarm), /DeleteItem/);
    assert.doesNotMatch(JSON.stringify(tableAlarm), /PutItem/);
    assert.doesNotMatch(JSON.stringify(tableAlarm), /Query/);
  });

  it('sets deployable default production capacity, throttles, and retention', () => {
    const stack = template('prod');
    stack.hasResourceProperties('AWS::CloudWatch::Alarm', {
      MetricName: 'RelayRejections',
      Namespace: 'RemoteDavinci/prod',
    });
    stack.hasResourceProperties('AWS::Logs::MetricFilter', {
      MetricTransformations: [
        {
          DefaultValue: 0,
          MetricName: 'RelayRejections',
          MetricNamespace: 'RemoteDavinci/prod',
          MetricValue: '1',
        },
      ],
    });
    stack.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: {
        DeletionProtectionEnabled: true,
        OnDemandThroughput: {
          MaxReadRequestUnits: 30_000,
          MaxWriteRequestUnits: 8_000,
        },
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      },
    });
    stack.resourceCountIs('AWS::Logs::LogGroup', 2);
    stack.hasResource('AWS::Logs::LogGroup', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: { RetentionInDays: 30 },
    });
    stack.hasResourceProperties('AWS::Lambda::Function', {
      LoggingConfig: {
        ApplicationLogLevel: 'WARN',
        LogFormat: 'JSON',
        SystemLogLevel: 'WARN',
      },
    });
    stack.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
      RouteSettings: {
        '$connect': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 500,
          ThrottlingRateLimit: 400,
        },
        '$default': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 1_000,
          ThrottlingRateLimit: 500,
        },
        '$disconnect': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 1_000,
          ThrottlingRateLimit: 500,
        },
        'pair.frame': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 1_000,
          ThrottlingRateLimit: 500,
        },
        'session.frame': {
          DataTraceEnabled: false,
          DetailedMetricsEnabled: false,
          ThrottlingBurstLimit: 5_000,
          ThrottlingRateLimit: 4_000,
        },
      },
    });
    const tables = Object.values(stack.findResources('AWS::DynamoDB::Table'));
    assert.equal(tables.length, 1);
    assert.equal(tables[0]?.Properties.WarmThroughput, undefined);
    const functions = Object.values(stack.findResources('AWS::Lambda::Function'));
    assert.equal(functions.length, 1);
    assert.equal(functions[0]?.Properties.ReservedConcurrentExecutions, undefined);
    const stages = Object.values(stack.findResources('AWS::ApiGatewayV2::Stage'));
    assert.equal(stages.length, 1);
    const accessLogSettings = stages[0]?.Properties.AccessLogSettings;
    assert.ok(accessLogSettings);
    const renderedAccessLogSettings = JSON.stringify(accessLogSettings);
    assert.match(renderedAccessLogSettings, /requestId/);
    assert.match(renderedAccessLogSettings, /routeKey/);
    assert.doesNotMatch(renderedAccessLogSettings, /connectionId/);
    assert.doesNotMatch(renderedAccessLogSettings, /apiId/);
    const accessLog = Object.entries(
      stack.findResources('AWS::Logs::LogGroup'),
    ).find(([id]) => id.startsWith('AccessLogs'));
    assert.ok(accessLog);
    assert.equal(accessLog[1].DeletionPolicy, 'Retain');
    assert.equal(accessLog[1].Properties.RetentionInDays, 7);
    for (const alarm of Object.values(
      stack.findResources('AWS::CloudWatch::Alarm'),
    )) {
      assert.deepEqual(alarm.Properties.AlarmActions, [testAlarmTopicArn]);
    }
  });

  it('can disable production access logging only when explicitly requested', () => {
    const stack = template('prod', false);
    stack.resourceCountIs('AWS::Logs::LogGroup', 1);
    const stages = Object.values(stack.findResources('AWS::ApiGatewayV2::Stage'));
    assert.equal(stages.length, 1);
    assert.equal(stages[0]?.Properties.AccessLogSettings, undefined);
  });

  it('requires production alarm delivery in the deployment account and region', () => {
    const app = new App();
    assert.throws(
      () =>
        new RendezvousRelayStack(app, 'MissingAlarmTopic', {
          environment: 'prod',
          env: { account: testAccount, region: testRegion },
        }),
      /requires an existing SNS alarm topic ARN/,
    );
    assert.throws(
      () =>
        new RendezvousRelayStack(app, 'WrongAlarmTopic', {
          alarmTopicArn: `arn:aws:sns:us-west-2:${testAccount}:alerts`,
          environment: 'prod',
          env: { account: testAccount, region: testRegion },
        }),
      /must match the deployment account and region/,
    );
  });

  it('tags runtime resources by project and environment', () => {
    const stack = template();
    const tagMatch = Match.arrayWith([
      { Key: 'Environment', Value: 'dev' },
      { Key: 'Project', Value: 'remote-davinci' },
    ]);
    stack.hasResourceProperties('AWS::DynamoDB::Table', { Tags: tagMatch });
    stack.hasResourceProperties('AWS::Lambda::Function', { Tags: tagMatch });
  });
});

describe('deploymentConfig', () => {
  it('requires an explicit matching production account, region, and alarm topic', () => {
    assert.throws(
      () =>
        deploymentConfig(
          new App({ context: { environment: 'prod' } }),
          {},
        ),
      /productionAccount/,
    );
    const context = {
      alarmTopicArn: testAlarmTopicArn,
      environment: 'prod',
      productionAccount: testAccount,
      productionRegion: testRegion,
    };
    assert.throws(
      () => deploymentConfig(new App({ context }), {}),
      /does not match CDK_DEFAULT_ACCOUNT/,
    );
    assert.throws(
      () =>
        deploymentConfig(new App({ context }), {
          CDK_DEFAULT_ACCOUNT: testAccount,
          CDK_DEFAULT_REGION: 'us-west-2',
        }),
      /does not match CDK_DEFAULT_REGION/,
    );
    assert.deepEqual(
      deploymentConfig(new App({ context }), {
        CDK_DEFAULT_ACCOUNT: testAccount,
        CDK_DEFAULT_REGION: testRegion,
      }),
      {
        account: testAccount,
        alarmTopicArn: testAlarmTopicArn,
        environment: 'prod',
        region: testRegion,
      },
    );
  });

  it('keeps development synthesis local-friendly', () => {
    assert.deepEqual(deploymentConfig(new App(), {}), {
      environment: 'dev',
      region: 'us-east-1',
    });
  });
});
