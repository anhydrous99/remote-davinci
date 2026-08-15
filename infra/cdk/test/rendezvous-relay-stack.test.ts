import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
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
    for (const resource of Object.values(
      stack.findResources('AWS::Lambda::Function'),
    )) {
      assert.deepEqual(resource.Properties.Architectures, ['arm64']);
      assert.equal(resource.Properties.Handler, 'bootstrap');
      assert.equal(resource.Properties.Runtime, 'provided.al2023');
    }
    for (const log of Object.values(
      stack.findResources('AWS::Logs::LogGroup'),
    )) {
      assert.equal(log.Properties.RetentionInDays, 7);
    }
  });

  it('builds executable Linux ARM64 bootstrap assets', () => {
    template();
    for (const name of ['authorizer', 'relay']) {
      const bootstrap = path.join(__dirname, '../../../../.build', name, 'bootstrap');
      const bytes = fs.readFileSync(bootstrap);
      assert.deepEqual([...bytes.subarray(0, 4)], [0x7f, 0x45, 0x4c, 0x46]);
      assert.equal(bytes.readUInt16LE(18), 183);
      assert.notEqual(fs.statSync(bootstrap).mode & 0o111, 0);
    }
  });

  it('preserves the baseline resource logical IDs', () => {
    assert.deepEqual(
      Object.keys(template().toJSON().Resources).sort(),
      [
        'AccessLogs8B620ECA',
        'AccessLogsPolicyResourcePolicyA1E3EF94',
        'ApiConnectAuthorizerB9E9A2F0',
        'ApiF70053CD',
        'ApiServerErrorsDFE5B564',
        'ApiTestdevApiConnectAuthorizer5D3D6032PermissionB5E8E2AC',
        'ApiconnectRoute2B5B23F2',
        'ApiconnectRouteConnectIntegration7BCE6281',
        'ApiconnectRouteConnectIntegrationPermission18C9C2B7',
        'ApidefaultRoute40D195EB',
        'ApidefaultRouteDefaultIntegrationE3602C1B',
        'ApidefaultRouteDefaultIntegrationPermission0A3AC89E',
        'ApidisconnectRoute1C5CAB1B',
        'ApidisconnectRouteDisconnectIntegration815E8937',
        'ApidisconnectRouteDisconnectIntegrationPermission6F1ECF1B',
        'AuthorizerErrorsF0468F50',
        'AuthorizerHandler0112B303',
        'AuthorizerHandlerServiceRole5F40A014',
        'AuthorizerHandlerServiceRoleDefaultPolicy53DE31A6',
        'AuthorizerLogsBA5DABC9',
        'AuthorizerThrottlesB6216B06',
        'RelayErrors28574ADF',
        'RelayHandler744E9E85',
        'RelayHandlerServiceRoleB2144F3C',
        'RelayHandlerServiceRoleDefaultPolicy3D477D8A',
        'RelayLogs019433A2',
        'RelayThrottles80A74296',
        'Stage0E8C2AF5',
        'State1C20CC9A',
        'TableThrottlesCD44955A',
      ],
    );
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
