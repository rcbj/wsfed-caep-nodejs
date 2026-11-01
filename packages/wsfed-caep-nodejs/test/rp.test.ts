// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The relying party against the stub identity provider (test/stub-idp.ts): the sign-in request, the
// sign-in response in both WS-Trust shapes, clear and encrypted, and the ways a response is forged,
// replayed, misdirected or pushed into a browser that never asked for it.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DOMParser } from '@xmldom/xmldom';
import { RelyingParty, WsFedError, resolveConfig, type WsFedConfig } from '../src/index.ts';
import {
  IDP_ENTITY, PASSIVE, REALM, REPLY, RP_CERT, RP_KEY, IDP_CERT, assertionXml, encrypt, idpMetadata, saml11Assertion,
  signXml, signedAssertion, wresult, type MetadataOptions,
} from './stub-idp.ts';

function config(extra: Partial<WsFedConfig> = {}, metadata: MetadataOptions = {}): WsFedConfig {
  return { realm: REALM, replyUrl: REPLY, privateKey: RP_KEY, certificate: RP_CERT, idpMetadata: idpMetadata(metadata), ...extra };
}

/** POSTs a sign-in response to the reply URL, as the identity provider's auto-posting form does. */
async function post(rp: RelyingParty, result: string, requestId: string | undefined, wctx = requestId ? `id=${requestId}` : undefined) {
  const body: Record<string, string> = { wa: 'wsignin1.0', wresult: result };
  if (wctx !== undefined) body.wctx = wctx;
  return rp.handleReply({ method: 'POST', url: '/wsfed', body }, { requestId });
}

async function rejects(p: Promise<unknown>, code: string, pattern?: RegExp) {
  await assert.rejects(p, (err: unknown) => {
    assert.ok(err instanceof WsFedError, `expected a WsFedError, got ${String(err)}`);
    assert.equal(err.code, code, err.message);
    if (pattern) assert.match(err.message, pattern);
    return true;
  });
}

describe('configuration and metadata', () => {
  it('needs a realm, a reply URL and IdP metadata; a key pair is optional but must match', async () => {
    await rejects(RelyingParty.create({ ...config(), realm: '' }), 'config', /realm/);
    await rejects(RelyingParty.create({ ...config(), replyUrl: '/wsfed' }), 'config', /absolute/);
    await rejects(RelyingParty.create(config({ certificate: IDP_CERT })), 'config', /not for the private key/);
    await rejects(RelyingParty.create({ realm: REALM, replyUrl: REPLY, idpMetadata: idpMetadata(), privateKey: RP_KEY }), 'config', /together/);
    await rejects(RelyingParty.create({ realm: REALM, replyUrl: REPLY, idpMetadata: idpMetadata(), wantAssertionsEncrypted: true }), 'config', /needs privateKey/);
    const keyless = await RelyingParty.create({ realm: REALM, replyUrl: REPLY, idpMetadata: idpMetadata() });
    assert.doesNotMatch(keyless.metadata(), /KeyDescriptor/);
  });

  it('omits signals when it is left out or true, and the configuration still resolves', () => {
    const base = { realm: REALM, replyUrl: REPLY, idpMetadata: 'https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml' };
    const omitted = resolveConfig(base);
    assert.equal(Object.hasOwn(omitted, 'signals'), false);
    assert.equal(omitted.realm, REALM);
    assert.equal(omitted.replyUrl, REPLY);
    assert.equal(omitted.requestTokenType, true);
    const on = resolveConfig({ ...base, signals: true });
    assert.equal(Object.hasOwn(on, 'signals'), false);
    assert.deepEqual(on, omitted);
  });

  it('records signals false and still resolves the WS-Federation fields', () => {
    const base = { realm: REALM, replyUrl: REPLY, idpMetadata: 'https://idp.example/FederationMetadata/2007-06/FederationMetadata.xml' };
    const off = resolveConfig({ ...base, signals: false });
    assert.equal(off.signals, false);
    const { signals, ...rest } = off;
    assert.equal(signals, false);
    assert.deepEqual(rest, resolveConfig(base));
    assert.equal(off.realm, REALM);
    assert.equal(off.replyUrl, REPLY);
    assert.equal(off.idpMetadata, base.idpMetadata);
  });

  it('refuses a signals value that is not true or false', () => {
    const base = { realm: REALM, replyUrl: REPLY, idpMetadata: 'https://idp.example/metadata' };
    assert.throws(() => resolveConfig({ ...base, signals: 'no' as unknown as boolean }), (err: unknown) => {
      assert.ok(err instanceof WsFedError);
      assert.equal(err.code, 'config');
      assert.equal(err.message, 'signals must be true or false');
      return true;
    });
  });

  it('reads the security token service role: its passive endpoint, token types and signing key', async () => {
    const rp = await RelyingParty.create(config());
    assert.equal(rp.idp.entityId, IDP_ENTITY);
    assert.equal(rp.idp.passiveRequestorEndpoint, PASSIVE);
    assert.ok(rp.idp.tokenTypesOffered.includes('urn:oasis:names:tc:SAML:2.0:assertion'));
    assert.equal(rp.idp.signingCertificates.length, 1);
  });

  it('resolves xsi:type by namespace, takes the key from IDPSSODescriptor when the STS role has none', async () => {
    assert.equal((await RelyingParty.create(config({}, { fedPrefix: 'wsfed' }))).idp.passiveRequestorEndpoint, PASSIVE);
    assert.equal((await RelyingParty.create(config({}, { keyIn: 'idpsso' }))).idp.signingCertificates.length, 1);
  });

  it('refuses metadata with no STS role, or one that offers no SAML 2.0 token', async () => {
    await rejects(RelyingParty.create(config({}, { noSts: true })), 'metadata', /SecurityTokenServiceType/);
    await rejects(RelyingParty.create(config({}, { tokenTypes: ['urn:oasis:names:tc:SAML:1.0:assertion'] })), 'metadata', /no SAML 2.0/);
  });

  it('writes an ApplicationServiceType role with the realm, the reply URL and the encryption key', async () => {
    const rp = await RelyingParty.create(config());
    const xml = rp.metadata();
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    const root = doc.documentElement!;
    assert.equal(root.getAttribute('entityID'), REALM);
    const role = root.getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:metadata', 'RoleDescriptor')[0]!;
    assert.equal(role.getAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'type'), 'fed:ApplicationServiceType');
    assert.match(xml, new RegExp(`<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>${REPLY}</wsa:Address>`));
    assert.match(xml, new RegExp(`<fed:TargetScopes><wsa:EndpointReference><wsa:Address>${REALM}</wsa:Address>`));
    assert.match(xml, /<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*<\/md:KeyDescriptor>/);
  });
});

describe('the sign-in request (wsignin1.0)', () => {
  it('names the realm, the reply URL, a wctx carrying the request id, and asks for SAML 2.0 by wreq', async () => {
    const rp = await RelyingParty.create(config());
    const req = rp.login({ relayState: '/home é' });
    const url = new URL(req.url);
    assert.equal(url.origin + url.pathname, PASSIVE);
    assert.equal(url.searchParams.get('wa'), 'wsignin1.0');
    assert.equal(url.searchParams.get('wtrealm'), REALM);
    assert.equal(url.searchParams.get('wreply'), REPLY);
    const wctx = new URLSearchParams(url.searchParams.get('wctx')!);
    assert.equal(wctx.get('id'), req.id);
    assert.equal(wctx.get('ru'), '/home é');
    assert.match(url.searchParams.get('wreq')!, /<wst:TokenType>urn:oasis:names:tc:SAML:2.0:assertion<\/wst:TokenType>/);
    assert.match(url.searchParams.get('wct')!, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.equal(url.searchParams.get('wfresh'), null);
  });

  it('forceAuthn is wfresh=0; wauth, whr and extra parameters go along; the protocol\'s own cannot be replaced', async () => {
    const rp = await RelyingParty.create(config({ requestTokenType: false }));
    const url = new URL(rp.login({ forceAuthn: true, authenticationMethod: 'http://schemas.microsoft.com/claims/multipleauthn', homeRealm: 'urn:partner', params: { login_hint: 'alice' } }).url);
    assert.equal(url.searchParams.get('wfresh'), '0');
    assert.equal(url.searchParams.get('wauth'), 'http://schemas.microsoft.com/claims/multipleauthn');
    assert.equal(url.searchParams.get('whr'), 'urn:partner');
    assert.equal(url.searchParams.get('login_hint'), 'alice');
    assert.equal(url.searchParams.get('wreq'), null, 'requestTokenType: false sends no wreq');
    assert.throws(() => rp.login({ params: { wtrealm: 'urn:evil' } }), /protocol's own/);
    assert.throws(() => rp.login({ relayState: 'x'.repeat(1025) }), /1024 bytes/);
  });

  it('signs out at the identity provider with wsignout1.0', async () => {
    const rp = await RelyingParty.create(config());
    const url = new URL(rp.logout({ reply: 'https://rp.test/' }));
    assert.equal(url.searchParams.get('wa'), 'wsignout1.0');
    assert.equal(url.searchParams.get('wtrealm'), REALM);
    assert.equal(url.searchParams.get('wreply'), 'https://rp.test/');
  });
});

describe('the sign-in response', () => {
  it('a signed SAML 2.0 assertion in a WS-Trust 2005/02 response: who signed in, with claims', async () => {
    const rp = await RelyingParty.create(config());
    const req = rp.login({ relayState: '/home' });
    const who = await post(rp, wresult(), req.id, req.wctx);
    assert.equal(who.nameId, 'alice-1234');
    assert.equal(who.nameIdFormat, 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
    assert.equal(who.sessionIndex, '_session1');
    assert.equal(who.relayState, '/home');
    assert.equal(who.requestId, req.id);
    assert.equal(who.trustVersion, '2005/02');
    assert.equal(who.realm, REALM);
    assert.equal(who.encrypted, false);
    assert.deepEqual(who.attributes['http://schemas.microsoft.com/ws/2008/06/identity/claims/role'], ['staff', 'admins']);
    assert.equal(who.attributeFriendlyNames['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'], 'mail');
    assert.equal(who.authnContextClassRef, 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport');
  });

  it('reads a WS-Trust 1.3 RequestSecurityTokenResponseCollection, and a raw form body', async () => {
    const rp = await RelyingParty.create(config());
    assert.equal((await post(rp, wresult({ trust: '1.3' }), '_r')).trustVersion, '1.3');
    const raw = new URLSearchParams({ wa: 'wsignin1.0', wresult: wresult(), wctx: 'id=_s' }).toString();
    assert.equal((await rp.handleReply({ method: 'POST', url: '/wsfed', body: raw }, { requestId: ['_x', '_s'] })).nameId, 'alice-1234');
  });

  it('accepts an assertion with no Recipient, and refuses one for another reply URL', async () => {
    const rp = await RelyingParty.create(config());
    assert.equal((await post(rp, wresult({ token: signedAssertion({ recipient: null }).xml }), '_r')).nameId, 'alice-1234');
    await rejects(post(rp, wresult({ token: signedAssertion({ recipient: 'https://other.test/wsfed' }).xml }), '_r'), 'validation', /Recipient/);
  });

  it('accepts a bare bearer confirmation, as iya-sts issues it, bounded by the Conditions', async () => {
    const rp = await RelyingParty.create(config());
    const who = await post(rp, wresult({ token: signedAssertion({ bareConfirmation: true }).xml }), '_r');
    assert.equal(who.nameId, 'alice-1234');
    assert.ok(who.notOnOrAfter.getTime() > Date.now());
    await rejects(post(rp, wresult({ token: signedAssertion({ bareConfirmation: true, notOnOrAfterMs: -120_000 }).xml }), '_r'), 'validation', /expired/);
    await rejects(post(rp, wresult({ token: signedAssertion({ bareConfirmation: true, noConditionsExpiry: true }).xml }), '_r'), 'validation', /nothing|no Conditions NotOnOrAfter/);
  });

  it('refuses an unsigned assertion: in WS-Federation its signature is the only one', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult({ token: assertionXml().xml }), '_r'), 'validation', /not signed/);
  });

  it('refuses an assertion altered after it was signed, or signed by another key', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult({ token: signedAssertion().xml.replace('alice-1234', 'mallory') }), '_r'), 'signature');
    const a = assertionXml();
    await rejects(post(rp, wresult({ token: signXml(a.xml, a.id, RP_KEY, RP_CERT) }), '_r'), 'signature', /does not verify/);
  });

  it('is not fooled by signature wrapping', async () => {
    const rp = await RelyingParty.create(config());
    const signed = signedAssertion();
    const forged = assertionXml({ nameId: 'mallory' }).xml;
    // Two tokens: refused outright.
    await rejects(post(rp, wresult({ token: forged + signed.xml }), '_r'), 'message', /exactly one/);
    // The forged one carrying the signed one's ID, the signed one hidden inside it.
    const hidden = forged.replace(/ID="[^"]+"/, `ID="${signed.id}"`).replace('</saml:Assertion>', `<saml:Advice>${signed.xml}</saml:Advice></saml:Assertion>`);
    await rejects(post(rp, wresult({ token: hidden }), '_r'), 'signature', /two elements/);
    // The signed one's ID given to a WS-Trust element as wsu:Id, which xml-crypto would also resolve.
    const decoy = wresult({ token: signed.xml }).replace('<t:Lifetime>', `<t:Lifetime xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="${signed.id}">`);
    await rejects(post(rp, decoy, '_r'), 'signature', /two elements/);
    // The signature moved onto the forged assertion: its reference points at another ID.
    const sigXml = /<ds:Signature[\s\S]*<\/ds:Signature>/.exec(signed.xml)![0];
    await rejects(post(rp, wresult({ token: forged.replace(/(<\/saml:Issuer>)/, `$1${sigXml}`) }), '_r'), 'signature', /refers to/);
  });

  it('refuses an assertion for another realm, from another issuer, or that has expired', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult({ token: signedAssertion({ audience: 'https://other.test/' }).xml }), '_r'), 'validation', /not for/);
    await rejects(post(rp, wresult({ token: signedAssertion({ issuer: 'https://evil.test' }).xml }), '_r'), 'validation', /issued by/);
    await rejects(post(rp, wresult({ token: signedAssertion({ notOnOrAfterMs: -120_000 }).xml }), '_r'), 'validation', /expired/);
    await rejects(post(rp, wresult({ appliesTo: 'https://other.test/' }), '_r'), 'validation', /applies to/);
    await rejects(post(rp, wresult({ expiresMs: -120_000 }), '_r'), 'validation', /response expired/);
  });

  it('refuses an assertion that answers a SAML AuthnRequest (InResponseTo): it belongs to another exchange', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult({ token: signedAssertion({ inResponseTo: '_samlreq' }).xml }), '_r'), 'validation', /InResponseTo/);
  });

  it('refuses a SAML 1.1 token, a token of another type, and anything not a WS-Trust response', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult({ token: saml11Assertion(), tokenType: 'urn:oasis:names:tc:SAML:2.0:assertion' }), '_r'), 'message', /SAML 1\.1/);
    await rejects(post(rp, wresult({ tokenType: 'urn:oasis:names:tc:SAML:1.0:assertion' }), '_r'), 'message', /SAML 2\.0 assertions only/);
    await rejects(post(rp, signedAssertion().xml, '_r'), 'message', /not a WS-Trust/);
    await rejects(post(rp, `<!DOCTYPE x [<!ENTITY e "x">]>${wresult()}`, '_r'), 'xml', /DOCTYPE/);
  });

  it('refuses a response to a sign-in this browser did not start, and an unsolicited one unless allowed', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(post(rp, wresult(), '_other', 'id=_r'), 'validation', /not a sign-in this browser/);
    await rejects(post(rp, wresult(), undefined, 'id=_r'), 'validation', /not a sign-in this browser/);
    await rejects(post(rp, wresult(), undefined), 'validation', /unsolicited/);
    const open = await RelyingParty.create(config({ allowUnsolicited: true }));
    const who = await post(open, wresult(), undefined, 'ru=%2Fthere');
    assert.equal(who.requestId, undefined);
    assert.equal(who.relayState, '/there');
  });

  it('refuses the same assertion twice', async () => {
    const rp = await RelyingParty.create(config());
    const result = wresult();
    await post(rp, result, '_r');
    await rejects(post(rp, result, '_r'), 'replay');
  });

  it('decrypts an encrypted assertion: EncryptedAssertion, and AD FS\'s bare EncryptedData', async () => {
    const rp = await RelyingParty.create(config());
    for (const cipher of ['aes-256-gcm', 'aes-128-cbc'] as const) {
      const who = await post(rp, wresult({ token: encrypt(signedAssertion().xml, cipher) }), '_r');
      assert.equal(who.nameId, 'alice-1234', cipher);
      assert.equal(who.encrypted, true);
    }
    assert.equal((await post(rp, wresult({ token: encrypt(signedAssertion().xml, 'aes-256-gcm', 'oaep256', null) }), '_r')).encrypted, true);
  });

  it('wantAssertionsEncrypted refuses a clear assertion; an altered ciphertext and an encrypted unsigned one are refused', async () => {
    const rp = await RelyingParty.create(config({ wantAssertionsEncrypted: true }));
    await rejects(post(rp, wresult(), '_r'), 'validation', /not encrypted/);
    await rejects(post(rp, wresult({ token: encrypt(assertionXml().xml) }), '_r'), 'validation', /not signed/);
    const enc = encrypt(signedAssertion().xml);
    const values = [...enc.matchAll(/<xenc:CipherValue>([^<]+)<\/xenc:CipherValue>/g)];
    const last = values[values.length - 1]![1]!;
    const bytes = Buffer.from(last, 'base64');
    bytes[20] = bytes[20]! ^ 1;
    await rejects(post(rp, wresult({ token: enc.replace(last, bytes.toString('base64')) }), '_r'), 'decryption');
  });

  it('an encrypted assertion needs a key; an EncryptedAttribute is decrypted', async () => {
    const keyless = await RelyingParty.create({ realm: REALM, replyUrl: REPLY, idpMetadata: idpMetadata() });
    await rejects(post(keyless, wresult({ token: encrypt(signedAssertion().xml) }), '_r'), 'decryption', /no privateKey/);
    const rp = await RelyingParty.create(config());
    const secret = encrypt('<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="employeeNumber"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>', 'aes-256-gcm', 'oaep256', 'EncryptedAttribute');
    const a = assertionXml({ extraAttributes: secret });
    assert.deepEqual((await post(rp, wresult({ token: signXml(a.xml, a.id) }), '_r')).attributes.employeeNumber, ['E-42']);
  });
});

describe('the reply URL', () => {
  it('refuses a GET, a wrong wa, wresultptr and a missing wresult', async () => {
    const rp = await RelyingParty.create(config());
    await rejects(rp.handleReply({ method: 'GET', url: `/wsfed?wa=wsignin1.0&wresult=${encodeURIComponent(wresult())}` }), 'message', /POSTed/);
    await rejects(rp.handleReply({ method: 'POST', url: '/wsfed', body: { wa: 'wattr1.0', wresult: wresult() } }), 'message', /not wsignin1.0/);
    await rejects(rp.handleReply({ method: 'POST', url: '/wsfed', body: { wa: 'wsignin1.0', wresultptr: 'https://evil.test/' } }), 'message', /wresultptr/);
    await rejects(rp.handleReply({ method: 'POST', url: '/wsfed', body: { wa: 'wsignin1.0' } }), 'message', /no wresult/);
  });

  it('recognizes the identity provider\'s sign-out cleanup', async () => {
    const rp = await RelyingParty.create(config());
    assert.equal(rp.isSignOutCleanup({ method: 'GET', url: '/wsfed?wa=wsignoutcleanup1.0' }), true);
    assert.equal(rp.isSignOutCleanup({ method: 'POST', url: '/wsfed', body: 'wa=wsignout1.0' }), true);
    assert.equal(rp.isSignOutCleanup({ method: 'POST', url: '/wsfed', body: { wa: 'wsignin1.0' } }), false);
    await rejects(rp.handleReply({ method: 'GET', url: '/wsfed?wa=wsignoutcleanup1.0' }), 'message', /sign-out/);
  });
});
