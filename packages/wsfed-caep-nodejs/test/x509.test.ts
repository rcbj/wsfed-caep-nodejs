// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The self-signed certificate generate-keys makes, and its command-line defaults.

import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { main } from '../src/cli.ts';
import { createSelfSignedKeyPair } from '../src/index.ts';

const der = (c: X509Certificate) => c.raw;
const SKI = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0e]);
const AKI = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x23]);

/** The 20-byte value after an extension's OID, as this module writes it. */
function keyIdAfter(cert: Buffer, oid: Buffer): Buffer {
  const at = cert.indexOf(oid);
  assert.ok(at > 0, 'the extension is present');
  const id = cert.subarray(at + oid.length).indexOf(Buffer.from([0x14]));   // a 20-byte value's length
  return cert.subarray(at + oid.length + id + 1, at + oid.length + id + 21);
}

describe('the self-signed certificate', () => {
  it('signs itself, and names its own key in subject and authority key identifiers', () => {
    const pair = createSelfSignedKeyPair({ commonName: 'rp', bits: 2048 });
    assert.ok(pair.certificate.verify(pair.certificate.publicKey));
    // RFC 5280 4.2.1.2 method 1: SHA-1 of the subjectPublicKey bits (for RSA, the RSAPublicKey DER).
    const rsaPublicKey = pair.certificate.publicKey.export({ type: 'pkcs1', format: 'der' });
    const want = createHash('sha1').update(rsaPublicKey).digest();
    assert.deepEqual(keyIdAfter(der(pair.certificate), SKI), want);
    assert.deepEqual(keyIdAfter(der(pair.certificate), AKI), want);
  });

  it('gives two certificates of one name different key identifiers, so a truststore can tell them apart', () => {
    const a = createSelfSignedKeyPair({ commonName: 'localhost:3000', bits: 2048 });
    const b = createSelfSignedKeyPair({ commonName: 'localhost:3000', bits: 2048 });
    assert.equal(a.certificate.subject, b.certificate.subject);
    assert.notDeepEqual(keyIdAfter(der(a.certificate), SKI), keyIdAfter(der(b.certificate), SKI));
  });

  it('generate-keys names the certificate after the realm, not after its host', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'wsfed-keys-'));
    const config = join(dir, 'wsfed.json');
    writeFileSync(config, JSON.stringify({ realm: 'http://localhost:3000/', replyUrl: 'http://localhost:3000/wsfed', idpMetadata: 'x', privateKey: 'k.pem', certificate: 'c.pem' }));
    await main(['generate-keys', '--config', config, '--bits', '2048'], () => {});
    const cert = new X509Certificate(readFileSync(join(dir, 'c.pem')));
    assert.equal(cert.subject, 'CN=wsfed-caep-nodejs relying party http://localhost:3000/');
  });
});
