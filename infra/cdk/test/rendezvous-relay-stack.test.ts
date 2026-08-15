import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

function template(environment: 'dev' | 'prod' = 'dev'): Template {
  const app = new App();
  return Template.fromStack(
    new RendezvousRelayStack(app, `Test-${environment}`, { environment }),
  );
}

describe('RendezvousRelayStack', () => {
  it('contains only the requested serverless boundary', () => {
    const stack = template();

    stack.resourceCountIs('AWS::DynamoDB::Table', 1);
    stack.resourceCountIs('AWS::Lambda::Function', 2);
    stack.resourceCountIs('AWS::Logs::LogGroup', 3);
    stack.resourceCountIs('AWS::ApiGatewayV2::Api', 1);
    stack.resourceCountIs('AWS::ApiGatewayV2::Route', 3);
    stack.resourceCountIs('AWS::CloudWatch::Alarm', 6);
    stack.resourceCountIs('AWS::SQS::Queue', 0);
    stack.resourceCountIs('AWS::EC2::VPC', 0);
    stack.resourceCountIs('AWS::Cognito::UserPool', 0);

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
    for (const routeKey of ['$connect', '$disconnect', '$default']) {
      stack.hasResourceProperties('AWS::ApiGatewayV2::Route', { RouteKey: routeKey });
    }
    stack.hasResourceProperties('AWS::ApiGatewayV2::Route', {
      AuthorizationType: 'CUSTOM',
      AuthorizerId: Match.anyValue(),
      RouteKey: '$connect',
    });
    stack.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
      DefaultRouteSettings: {
        DataTraceEnabled: false,
        DetailedMetricsEnabled: true,
        ThrottlingBurstLimit: 100,
        ThrottlingRateLimit: 50,
      },
      StageName: 'v1',
    });
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
    for (const log of Object.values(
      stack.findResources('AWS::Logs::LogGroup'),
    )) {
      assert.equal(log.Properties.RetentionInDays, 7);
    }
  });

  it('protects connect and scopes runtime permissions', () => {
    const json = template().toJSON();
    const policies = Object.values(json.Resources).filter(
      (resource): resource is Record<string, unknown> =>
        (resource as { Type?: string }).Type === 'AWS::IAM::Policy',
    );
    const rendered = JSON.stringify(policies);

    assert.match(rendered, /execute-api:ManageConnections/);
    assert.match(rendered, /dynamodb:GetItem/);
    assert.doesNotMatch(rendered, /dynamodb:Scan/);
    template().hasResourceProperties('AWS::ApiGatewayV2::Authorizer', {
      AuthorizerType: 'REQUEST',
      IdentitySource: ['route.request.header.Authorization'],
    });
  });

  it('retains and protects production state', () => {
    const stack = template('prod');
    stack.hasResource('AWS::DynamoDB::Table', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
      Properties: {
        DeletionProtectionEnabled: true,
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      },
    });
    for (const log of Object.values(
      stack.findResources('AWS::Logs::LogGroup'),
    )) {
      assert.equal(log.DeletionPolicy, 'Retain');
      assert.equal(log.Properties.RetentionInDays, 90);
    }
  });
});
