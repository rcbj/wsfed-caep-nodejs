// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// A stub WS-Federation identity provider for the tests: it publishes federation metadata, writes SAML 2.0
// assertions the way a security token service does, signs them with its own key, encrypts them, and wraps
// them in a WS-Trust RequestSecurityTokenResponse (February 2005, or 1.3 in a collection) as the wresult
// of a sign-in response. It shares no code with the library except xml-crypto, the signing engine.

import { createCipheriv, createPublicKey, publicEncrypt, randomBytes, constants, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SignedXml } from 'xml-crypto';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
export const RP_KEY = fixture('rp.key');
export const RP_CERT = fixture('rp.crt');
export const IDP_KEY = fixture('idp.key');
export const IDP_CERT = fixture('idp.crt');

export const IDP_ENTITY = 'https://idp.test';
export const PASSIVE = 'https://idp.test/wsfed';
export const REALM = 'https://rp.test/';
export const REPLY = 'https://rp.test/wsfed';

const body = (pem: string) => pem.replace(/-----(BEGIN|END) CERTIFICATE-----|\s+/g, '');
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString();
const id = () => `_${randomBytes(16).toString('hex')}`;

export interface MetadataOptions {
  /** Where the signing key is published: the STS role (default), or only the IDPSSODescriptor. */
  keyIn?: 'sts' | 'idpsso';
  /** The token types offered. */
  tokenTypes?: string[];
  /** The prefix the fed namespace is bound to, to check xsi:type is resolved, not matched as text. */
  fedPrefix?: string;
  /** Leave the STS role out. */
  noSts?: boolean;
}

/** Federation metadata as iya-sts and AD FS publish it: the STS role, and the same entity's SAML 2.0 IdP role. */
export function idpMetadata(o: MetadataOptions = {}): string {
  const fed = o.fedPrefix ?? 'fed';
  const key = `<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${body(IDP_CERT)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`;
  const types = (o.tokenTypes ?? ['urn:oasis:names:tc:SAML:1.0:assertion', 'urn:oasis:names:tc:SAML:2.0:assertion'])
    .map((t) => `<${fed}:TokenType Uri="${t}"/>`).join('');
  const sts = o.noSts ? '' : `
  <md:RoleDescriptor xsi:type="${fed}:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    ${o.keyIn === 'idpsso' ? '' : key}
    <${fed}:TokenTypesOffered>${types}</${fed}:TokenTypesOffered>
    <${fed}:SecurityTokenServiceEndpoint><wsa:EndpointReference><wsa:Address>https://idp.test/sts</wsa:Address></wsa:EndpointReference></${fed}:SecurityTokenServiceEndpoint>
    <${fed}:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>${PASSIVE}</wsa:Address></wsa:EndpointReference></${fed}:PassiveRequestorEndpoint>
  </md:RoleDescriptor>`;
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:${fed}="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" entityID="${IDP_ENTITY}">${sts}
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${key}
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.test/saml2/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

export interface AssertionOptions {
  audience?: string;
  recipient?: string | null;
  inResponseTo?: string;
  notOnOrAfterMs?: number;
  issuer?: string;
  nameId?: string;
  sessionIndex?: string;
  /** Extra AttributeStatement content (e.g. an EncryptedAttribute). */
  extraAttributes?: string;
  /** A bare bearer SubjectConfirmation, no SubjectConfirmationData: iya-sts's WS-Federation SAML 2.0 token. */
  bareConfirmation?: boolean;
  /** Leave NotOnOrAfter off the Conditions. */
  noConditionsExpiry?: boolean;
}

const CLAIMS = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims';

/** A SAML 2.0 assertion as a WS-Federation STS issues one: no InResponseTo, claim-URI attributes. */
export function assertionXml(o: AssertionOptions = {}): { xml: string; id: string } {
  const aid = id();
  const recipient = o.recipient === null ? '' : ` Recipient="${o.recipient ?? REPLY}"`;
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : '';
  const xml = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${aid}" Version="2.0" IssueInstant="${iso(0)}">`
    + `<saml:Issuer>${o.issuer ?? IDP_ENTITY}</saml:Issuer>`
    + `<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${o.nameId ?? 'alice-1234'}</saml:NameID>`
    + (o.bareConfirmation
      ? '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>'
      : `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${recipient} NotOnOrAfter="${iso(o.notOnOrAfterMs ?? 300_000)}"${irt}/></saml:SubjectConfirmation></saml:Subject>`)
    + `<saml:Conditions NotBefore="${iso(-5000)}"${o.noConditionsExpiry ? '' : ` NotOnOrAfter="${iso(o.notOnOrAfterMs ?? 300_000)}"`}><saml:AudienceRestriction><saml:Audience>${o.audience ?? REALM}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
    + `<saml:AttributeStatement><saml:Attribute Name="${CLAIMS}/nameidentifier"><saml:AttributeValue>urn:uuid:alice</saml:AttributeValue></saml:Attribute>`
    + `<saml:Attribute Name="${CLAIMS}/emailaddress" FriendlyName="mail"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>`
    + `<saml:Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>${o.extraAttributes ?? ''}</saml:AttributeStatement>`
    + `<saml:AuthnStatement AuthnInstant="${iso(-1000)}" SessionIndex="${o.sessionIndex ?? '_session1'}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`
    + '</saml:Assertion>';
  return { xml, id: aid };
}

/** Signs the element with this ID, enveloped, right after its Issuer. */
export function signXml(xml: string, elementId: string, key = IDP_KEY, cert = IDP_CERT): string {
  const sig = new SignedXml({ privateKey: key, publicCert: cert, signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256', canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#' });
  sig.addReference({ xpath: `//*[@ID='${elementId}']`, transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'], digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256' });
  sig.computeSignature(xml, { prefix: 'ds', location: { reference: `//*[@ID='${elementId}']/*[local-name(.)='Issuer']`, action: 'after' } });
  return sig.getSignedXml();
}

export function signedAssertion(o: AssertionOptions = {}): { xml: string; id: string } {
  const a = assertionXml(o);
  return { xml: signXml(a.xml, a.id), id: a.id };
}

/**
 * Encrypts XML to the relying party's certificate: as `<saml:EncryptedAssertion>` (or another wrapper), or
 * with `wrapper: null` as a bare `<xenc:EncryptedData>`, the way AD FS encrypts a WS-Federation token.
 */
export function encrypt(plain: string, cipher: 'aes-256-gcm' | 'aes-128-cbc' = 'aes-256-gcm', transport: 'mgf1p' | 'oaep256' = 'mgf1p', wrapper: string | null = 'EncryptedAssertion'): string {
  const key = randomBytes(cipher === 'aes-256-gcm' ? 32 : 16);
  let value: Buffer;
  let alg: string;
  if (cipher === 'aes-256-gcm') {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    value = Buffer.concat([iv, ct, c.getAuthTag()]);
    alg = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
  } else {
    const iv = randomBytes(16);
    const c = createCipheriv('aes-128-cbc', key, iv);
    value = Buffer.concat([iv, c.update(plain, 'utf8'), c.final()]);
    alg = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
  }
  const wrapped = publicEncrypt({ key: createPublicKey(new X509Certificate(RP_CERT).publicKey.export({ type: 'spki', format: 'pem' })), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: transport === 'mgf1p' ? 'sha1' : 'sha256' }, key);
  const keyMethod = transport === 'mgf1p'
    ? '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>'
    : '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></xenc:EncryptionMethod>';
  const data = '<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">'
    + `<xenc:EncryptionMethod Algorithm="${alg}"/>`
    + `<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey>${keyMethod}`
    + `<xenc:CipherData><xenc:CipherValue>${wrapped.toString('base64')}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>`
    + `<xenc:CipherData><xenc:CipherValue>${value.toString('base64')}</xenc:CipherValue></xenc:CipherData>`
    + '</xenc:EncryptedData>';
  return wrapper === null ? data : `<saml:${wrapper} xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${data}</saml:${wrapper}>`;
}

export interface ResultOptions {
  /** The token(s) in the RequestedSecurityToken. Default: a fresh signed assertion. */
  token?: string;
  /** `2005` (AD FS's and iya-sts's default) or `1.3` (a RequestSecurityTokenResponseCollection). */
  trust?: '2005' | '1.3';
  appliesTo?: string;
  tokenType?: string;
  expiresMs?: number;
}

/** The wresult of a sign-in response: a RequestSecurityTokenResponse around the token. */
export function wresult(o: ResultOptions = {}): string {
  const ns = o.trust === '1.3' ? 'http://docs.oasis-open.org/ws-sx/ws-trust/200512' : 'http://schemas.xmlsoap.org/ws/2005/02/trust';
  const token = o.token ?? signedAssertion().xml;
  const rstr = `<t:RequestSecurityTokenResponse xmlns:t="${ns}">`
    + `<t:Lifetime><wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${iso(0)}</wsu:Created><wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">${iso(o.expiresMs ?? 3600_000)}</wsu:Expires></t:Lifetime>`
    + `<wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy"><wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>${o.appliesTo ?? REALM}</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>`
    + `<t:RequestedSecurityToken>${token}</t:RequestedSecurityToken>`
    + `<t:TokenType>${o.tokenType ?? 'urn:oasis:names:tc:SAML:2.0:assertion'}</t:TokenType>`
    + `<t:RequestType>${ns}/Issue</t:RequestType><t:KeyType>${ns}/Bearer</t:KeyType>`
    + '</t:RequestSecurityTokenResponse>';
  return o.trust === '1.3' ? `<t:RequestSecurityTokenResponseCollection xmlns:t="${ns}">${rstr}</t:RequestSecurityTokenResponseCollection>` : rstr;
}

/** A SAML 1.1 assertion, as an identity provider issues by default to a WS-Federation relying party that does not ask. */
export function saml11Assertion(): string {
  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" MajorVersion="1" MinorVersion="1" AssertionID="${id()}" Issuer="${IDP_ENTITY}" IssueInstant="${iso(0)}">`
    + '<saml:AttributeStatement><saml:Subject><saml:NameIdentifier>alice</saml:NameIdentifier></saml:Subject></saml:AttributeStatement></saml:Assertion>';
}
