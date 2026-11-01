// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The setup script's plan, offline: what it registers, and where.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { MULTIPLE_ACCOUNTS, filesOf, ssfCalls, idpMetadataUrl, parseArgs, planFor, realmOf } from './configure-iya-sts.ts';
import { demoPort, endpointsFor, onPort } from './redirects.mjs';

describe('configure-iya-sts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'wsfed-setup-'));
  const config = join(dir, 'wsfed.json');
  writeFileSync(config, JSON.stringify({
    realm: 'http://localhost:3000/', replyUrl: 'http://localhost:3000/wsfed',
    privateKey: 'generated/rp.key', certificate: 'generated/rp.crt',
    idpMetadata: 'generated/idp-metadata.xml', idpCa: 'generated/idp-ca.pem',
  }));

  it('resolves the configuration\'s files next to it', () => {
    const files = filesOf(config);
    assert.equal(files.key, join(dir, 'generated/rp.key'));
    assert.equal(files.rpMetadata, join(dir, 'generated/rp-metadata.xml'));
    assert.equal(files.idpCa, join(dir, 'generated/idp-ca.pem'));
    assert.equal(files.replyUrl, 'http://localhost:3000/wsfed');
  });

  it('registers the realm for wsfed with its reply URL, and fetches the per-RP federation metadata', () => {
    const files = filesOf(config);
    const plan = planFor(files, 'https://localhost:8081', 'wsfed-demo-user');
    const create = plan[0]!;
    assert.match(create.path, /\/admin-api\/applications\/create$/);
    assert.deepEqual(create.body, {
      identifier: 'http://localhost:3000/', name: 'wsfed-caep-nodejs demo', protocols: ['wsfed'],
      fields: { wsfedRealm: ['http://localhost:3000/'], wsfedReplyUrl: ['http://localhost:3000/wsfed'] },
    });
    assert.deepEqual(plan[1]!.body, { application: 'http://localhost:3000/', attribute: 'wsfedReplyUrl', value: 'http://localhost:3000/wsfed' });
    assert.ok(plan.some((c) => c.path === 'https://localhost:8081/wsfed/metadata/http%3A%2F%2Flocalhost%3A3000%2F'));
    assert.deepEqual(plan.find((c) => c.path.endsWith('/admin-api/config/set'))?.body, MULTIPLE_ACCOUNTS);
    assert.match(plan[plan.length - 1]!.path, /\/users\/create$/);
    assert.equal(planFor(files, 'https://localhost:8081', '').some((c) => c.path.endsWith('/users/create')), false);
  });

  it('with an ssf block, gives the application Shared Signals access by its own certificate', () => {
    const withSsf = join(dir, 'wsfed-ssf.json');
    writeFileSync(withSsf, JSON.stringify({ ...JSON.parse(readFileSync(config, 'utf8')), ssf: { transmitter: 'https://localhost:8081' } }));
    const files = filesOf(withSsf);
    assert.equal(files.ssfTransmitter, 'https://localhost:8081');
    const calls = ssfCalls(files, 'https://localhost:8081', 'PEM');
    assert.deepEqual(calls.map((c) => c.path.replace('https://localhost:8081/admin-api', '')),
      ['/applications/add', '/roles/add-member', '/tls/trust/add', '/applications/add-certificate']);
    assert.deepEqual(calls[0]!.body, { application: 'http://localhost:3000/', attribute: 'oauthAllowedScope', value: 'ssf.manage' });
    assert.deepEqual(calls[1]!.body, { role: 'SSF_MANAGE', kind: 'application', member: 'http://localhost:3000/' });
    assert.ok(planFor(files, 'https://localhost:8081', '').some((c) => c.path.endsWith('/applications/add-certificate')));
    assert.ok(!planFor(filesOf(config), 'https://localhost:8081', '').some((c) => c.path.endsWith('/applications/add-certificate')), 'no ssf block, no access');
  });

  it('keeps a realm\'s base and refuses any other path', () => {
    assert.deepEqual(realmOf('https://idp.test/realm/acme'), { origin: 'https://idp.test', base: 'https://idp.test/realm/acme' });
    assert.throws(() => realmOf('https://idp.test/wsfed'), /realm/);
    assert.equal(idpMetadataUrl('https://idp.test/realm/acme', 'urn:x'), 'https://idp.test/realm/acme/wsfed/metadata/urn%3Ax');
  });

  it('takes its options, and refuses plain http', () => {
    const a = parseArgs(['--idp', 'https://idp.test/', '--public-url', 'http://app.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(a.idp, 'https://idp.test');
    assert.equal(a.publicUrl, 'http://app.test');
    assert.equal(a.publicUrlGiven, true);
    assert.equal(parseArgs([], {}).publicUrlGiven, false);
    assert.equal(parseArgs([], { PUBLIC_URL: 'http://demo.test' }).publicUrlGiven, true);
    assert.equal(a.testUser, '');
    assert.equal(a.dryRun, true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--public-url', ''], {}), /public-url/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });

  it('registers a loopback realm and reply URL on the port the demo listens on', () => {
    const moved = endpointsFor('http://localhost:3000/', 'http://localhost:3000/wsfed', { publicUrlGiven: false, port: 3001 });
    assert.equal(moved.realm, 'http://localhost:3001/');
    assert.equal(moved.replyUrl, 'http://localhost:3001/wsfed');
    assert.equal(onPort('http://127.0.0.1:3000/wsfed', 3001), 'http://127.0.0.1:3001/wsfed');
    assert.equal(onPort('http://[::1]:3000/wsfed', 3001), 'http://[::1]:3001/wsfed');
    assert.equal(onPort('not a url', 3001), 'not a url');
    const published = endpointsFor('https://app.example/', 'https://app.example/wsfed', { publicUrlGiven: false, port: 3001 });
    assert.equal(published.realm, 'https://app.example/');
    assert.equal(published.replyUrl, 'https://app.example/wsfed');
    const explicit = endpointsFor('http://localhost:3000/', 'http://localhost:3000/wsfed', { publicUrl: 'http://app.test:9', publicUrlGiven: true, port: 3001 });
    assert.equal(explicit.realm, 'http://app.test:9/');
    assert.equal(explicit.replyUrl, 'http://app.test:9/wsfed');
    assert.equal(demoPort('3000', '3001'), 3001);
    assert.equal(demoPort('3001', ''), 3001);
    assert.equal(demoPort('3002', 'nope'), 3002);
    assert.equal(demoPort('', undefined), undefined);
    assert.equal(demoPort('nope', undefined), undefined);
    const files = filesOf(config);
    const endpoints = endpointsFor(files.realm, files.replyUrl, { publicUrlGiven: false, port: 3001 });
    files.realm = endpoints.realm;
    files.replyUrl = endpoints.replyUrl;
    const plan = planFor(files, 'https://localhost:8081', '');
    const body = plan[0]!.body as { identifier: string; fields: { wsfedRealm: string[]; wsfedReplyUrl: string[] } };
    assert.equal(body.identifier, 'http://localhost:3001/');
    assert.deepEqual(body.fields.wsfedRealm, ['http://localhost:3001/']);
    assert.deepEqual(body.fields.wsfedReplyUrl, ['http://localhost:3001/wsfed']);
    assert.deepEqual(plan[1]!.body, { application: 'http://localhost:3001/', attribute: 'wsfedReplyUrl', value: 'http://localhost:3001/wsfed' });
    assert.ok(plan.some((c) => c.path === 'https://localhost:8081/wsfed/metadata/http%3A%2F%2Flocalhost%3A3001%2F'));
  });
});
