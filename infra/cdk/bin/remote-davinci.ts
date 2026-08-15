#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

const app = new App();
const environment = app.node.tryGetContext('environment') ?? 'dev';
const account = process.env.CDK_DEFAULT_ACCOUNT;
const region: unknown = app.node.tryGetContext('region') ?? 'us-east-1';

function booleanContext(name: string): boolean | undefined {
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

if (environment !== 'dev' && environment !== 'prod') {
  throw new Error('CDK context environment must be "dev" or "prod"');
}
if (typeof region !== 'string' || !region) {
  throw new Error('CDK context region must be a non-empty string');
}
const accessLogs = booleanContext('accessLogs');
const peakCapacity = booleanContext('peakCapacity');

new RendezvousRelayStack(app, `RemoteDavinci-${environment}`, {
  ...(accessLogs === undefined ? {} : { accessLogs }),
  environment,
  env: account ? { account, region } : { region },
  ...(peakCapacity === undefined ? {} : { peakCapacity }),
});
