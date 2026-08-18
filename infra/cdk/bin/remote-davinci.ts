#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

export interface DeploymentConfig {
  readonly environment: 'dev' | 'prod';
  readonly account?: string;
  readonly accessLogs?: boolean;
  readonly alarmTopicArn?: string;
  readonly region: string;
}

function booleanContext(app: App, name: string): boolean | undefined {
  const value: unknown = app.node.tryGetContext(name);
  if (
    value !== undefined &&
    typeof value !== 'boolean' &&
    value !== 'true' &&
    value !== 'false'
  ) {
    throw new Error(`CDK context ${name} must be true or false`);
  }
  return value === undefined ? undefined : value === true || value === 'true';
}

function stringContext(app: App, name: string): string | undefined {
  const value: unknown = app.node.tryGetContext(name);
  if (value !== undefined && (typeof value !== 'string' || value.length === 0)) {
    throw new Error(`CDK context ${name} must be a non-empty string`);
  }
  return value;
}

function requiredStringContext(app: App, name: string): string {
  const value = stringContext(app, name);
  if (value === undefined) {
    throw new Error(`Production requires CDK context ${name}`);
  }
  return value;
}

export function deploymentConfig(
  app: App,
  processEnvironment: NodeJS.ProcessEnv = process.env,
): DeploymentConfig {
  const environment: unknown = app.node.tryGetContext('environment') ?? 'dev';
  if (environment !== 'dev' && environment !== 'prod') {
    throw new Error('CDK context environment must be "dev" or "prod"');
  }

  const accessLogs = booleanContext(app, 'accessLogs');
  const alarmTopicArn = stringContext(app, 'alarmTopicArn');
  if (environment === 'prod') {
    const account = requiredStringContext(app, 'productionAccount');
    const region = requiredStringContext(app, 'productionRegion');
    const productionAlarmTopicArn = requiredStringContext(app, 'alarmTopicArn');
    if (!/^\d{12}$/.test(account)) {
      throw new Error('CDK context productionAccount must be a 12-digit AWS account ID');
    }
    if (processEnvironment.CDK_DEFAULT_ACCOUNT !== account) {
      throw new Error('Production account does not match CDK_DEFAULT_ACCOUNT');
    }
    if (processEnvironment.CDK_DEFAULT_REGION !== region) {
      throw new Error('Production region does not match CDK_DEFAULT_REGION');
    }
    return {
      ...(accessLogs === undefined ? {} : { accessLogs }),
      account,
      alarmTopicArn: productionAlarmTopicArn,
      environment,
      region,
    };
  }

  const region = stringContext(app, 'region') ?? 'us-east-1';
  return {
    ...(processEnvironment.CDK_DEFAULT_ACCOUNT === undefined
      ? {}
      : { account: processEnvironment.CDK_DEFAULT_ACCOUNT }),
    ...(accessLogs === undefined ? {} : { accessLogs }),
    ...(alarmTopicArn === undefined ? {} : { alarmTopicArn }),
    environment,
    region,
  };
}

export function main(): void {
  const app = new App();
  const config = deploymentConfig(app);
  new RendezvousRelayStack(app, `RemoteDavinci-${config.environment}`, {
    ...(config.accessLogs === undefined ? {} : { accessLogs: config.accessLogs }),
    ...(config.alarmTopicArn === undefined
      ? {}
      : { alarmTopicArn: config.alarmTopicArn }),
    environment: config.environment,
    env: config.account
      ? { account: config.account, region: config.region }
      : { region: config.region },
  });
}

if (require.main === module) {
  main();
}
