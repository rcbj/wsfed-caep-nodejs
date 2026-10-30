// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
// The setup script's plan, offline: what it registers, and where.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { MULTIPLE_ACCOUNTS, filesOf, ssfCalls, idpMetadataUrl, parseArgs, planFor, realmOf } from './configure-iya-sts.ts';

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
    const a = parseArgs(['--idp', 'https://idp.test/', '--no-test-user', '--dry-run'], {});
    assert.equal(a.idp, 'https://idp.test');
    assert.equal(a.testUser, '');
    assert.equal(a.dryRun, true);
    assert.throws(() => parseArgs(['--idp', 'http://idp.test'], {}), /https/);
    assert.throws(() => parseArgs(['--bogus'], {}), /Unknown argument/);
  });
});
