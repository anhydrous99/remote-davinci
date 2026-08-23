#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

export interface DeploymentConfig {
  readonly environment: 'dev' | 'prod';
  readonly account?: string;
  readonly accessLogs?: boolean;
  readonly alarmTopicArn?: string;
  readonly pairActivationsPerSourceHour?: number;
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

function positiveIntegerContext(app: App, name: string): number | undefined {
  const raw: unknown = app.node.tryGetContext(name);
  if (raw === undefined) return undefined;
  const value =
    typeof raw === 'string' && /^[1-9][0-9]*$/.test(raw)
      ? Number(raw)
      : raw;
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > 10_000
  ) {
    throw new Error(`CDK context ${name} must be an integer from 1 through 10000`);
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
  const pairActivationsPerSourceHour = positiveIntegerContext(
    app,
    'pairActivationsPerSourceHour',
  );
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
      ...(pairActivationsPerSourceHour === undefined
        ? {}
        : { pairActivationsPerSourceHour }),
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
    ...(pairActivationsPerSourceHour === undefined
      ? {}
      : { pairActivationsPerSourceHour }),
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
    ...(config.pairActivationsPerSourceHour === undefined
      ? {}
      : {
          pairActivationsPerSourceHour:
            config.pairActivationsPerSourceHour,
        }),
    environment: config.environment,
    env: config.account
      ? { account: config.account, region: config.region }
      : { region: config.region },
  });
}

if (require.main === module) {
  main();
}
