#!/usr/bin/env node
import { App } from 'aws-cdk-lib';
import { RendezvousRelayStack } from '../lib/rendezvous-relay-stack.js';

const app = new App();
const environment = app.node.tryGetContext('environment') ?? 'dev';
const account = process.env.CDK_DEFAULT_ACCOUNT;
const region: unknown = app.node.tryGetContext('region') ?? 'us-east-1';

if (environment !== 'dev' && environment !== 'prod') {
  throw new Error('CDK context environment must be "dev" or "prod"');
}
if (typeof region !== 'string' || !region) {
  throw new Error('CDK context region must be a non-empty string');
}

new RendezvousRelayStack(app, `RemoteDavinci-${environment}`, {
  environment,
  env: account ? { account, region } : { region },
});
