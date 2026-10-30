// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The XML this module reads and writes. Every message is parsed here, and a document with a DOCTYPE is
// refused before the parser sees it: neither WS-Federation nor SAML ever needs one, and a DTD is how
// entity expansion and external entities get in. Lookups are by namespace and local name, never by
// prefix, because the prefix is the sender's choice.

import { DOMParser, XMLSerializer } from '@xmldom/xmldom';
import { WsFedError } from './errors.ts';

export const NS = {
  saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
  saml1: 'urn:oasis:names:tc:SAML:1.0:assertion',
  md: 'urn:oasis:names:tc:SAML:2.0:metadata',
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  xenc: 'http://www.w3.org/2001/04/xmlenc#',
  xenc11: 'http://www.w3.org/2009/xmlenc11#',
  xsi: 'http://www.w3.org/2001/XMLSchema-instance',
  /** WS-Federation 1.2's metadata extensions. */
  fed: 'http://docs.oasis-open.org/wsfed/federation/200706',
  /** WS-Trust February 2005: what AD FS (and iya-sts by default) wrap the token in. */
  trust2005: 'http://schemas.xmlsoap.org/ws/2005/02/trust',
  /** WS-Trust 1.3 (ws-sx 200512): a RequestSecurityTokenResponseCollection around one response. */
  trust13: 'http://docs.oasis-open.org/ws-sx/ws-trust/200512',
  wsa: 'http://www.w3.org/2005/08/addressing',
  /** The August 2004 WS-Addressing draft, which older WS-Trust 2005/02 responses use. */
  wsa2004: 'http://schemas.xmlsoap.org/ws/2004/08/addressing',
  /** WS-Policy 2004/09 and 1.5, either of which holds a response's AppliesTo. */
  wsp: 'http://schemas.xmlsoap.org/ws/2004/09/policy',
  wsp15: 'http://www.w3.org/ns/ws-policy',
  wsu: 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
} as const;

/** The token type URIs that name a SAML 2.0 assertion. */
export const SAML2_TOKEN_TYPES: readonly string[] = [
  'urn:oasis:names:tc:SAML:2.0:assertion',
  'http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0',
];
export const SAML2_TOKEN_TYPE = 'urn:oasis:names:tc:SAML:2.0:assertion';

export const CM_BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

/** Parses a message or metadata document. Throws `xml` on anything malformed or carrying a DTD. */
export function parseXml(text: string, what = 'the message'): Document {
  if (/<!DOCTYPE|<!ENTITY/i.test(text)) {
    throw new WsFedError('xml', `${what} carries a DOCTYPE or an entity declaration, which WS-Federation never needs`);
  }
  const problems: string[] = [];
  const parser = new DOMParser({
    locator: {},
    errorHandler: {
      warning: () => {},
      error: (msg: string) => { problems.push(msg); },
      fatalError: (msg: string) => { problems.push(msg); },
    },
  });
  let doc: Document;
  try {
    doc = parser.parseFromString(text, 'application/xml') as unknown as Document;
  } catch (err) {
    throw new WsFedError('xml', `${what} is not well-formed XML: ${(err as Error).message}`, { cause: err });
  }
  if (problems.length || !doc || !doc.documentElement) {
    throw new WsFedError('xml', `${what} is not well-formed XML: ${problems[0] ?? 'no document element'}`);
  }
  return doc;
}

export function serialize(node: Node): string {
  return new XMLSerializer().serializeToString(node as never);
}

/** The element children of `el` with this namespace and local name. */
export function children(el: Element | Document, ns: string, local: string): Element[] {
  const out: Element[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1 && (n as Element).namespaceURI === ns && (n as Element).localName === local) out.push(n as Element);
  }
  return out;
}

/** Every element child of `el`, whatever its name. */
export function elementChildren(el: Element): Element[] {
  const out: Element[] = [];
  for (let n = el.firstChild; n; n = n.nextSibling) if (n.nodeType === 1) out.push(n as Element);
  return out;
}

/** The one child with this name, or undefined. More than one is refused: these are never repeated. */
export function child(el: Element, ns: string, local: string): Element | undefined {
  const found = children(el, ns, local);
  if (found.length > 1) throw new WsFedError('validation', `<${el.localName}> has more than one <${local}>`);
  return found[0];
}

/** Every element below `el` (at any depth) with this namespace and local name. */
export function descendants(el: Element | Document, ns: string, local: string): Element[] {
  return Array.from(el.getElementsByTagNameNS(ns, local) as unknown as ArrayLike<Element>);
}

export function text(el: Element | undefined): string {
  return (el?.textContent ?? '').trim();
}

export function attr(el: Element, name: string): string | undefined {
  return el.hasAttribute(name) ? el.getAttribute(name) ?? undefined : undefined;
}

/** The `wsa:Address` values below `el`, in either WS-Addressing namespace. */
export function wsaAddresses(el: Element): string[] {
  return [...descendants(el, NS.wsa, 'Address'), ...descendants(el, NS.wsa2004, 'Address')].map(text).filter(Boolean);
}

/** `true` when `el` is the element with this namespace and local name. */
export function is(el: Element | undefined, ns: string, local: string): boolean {
  return !!el && el.namespaceURI === ns && el.localName === local;
}

const ID_NAMES = new Set(['ID', 'Id', 'id']);

/**
 * Refuses a document in which two elements share an ID: that is how a signature is made to point
 * elsewhere. Any attribute whose LOCAL name is an ID name counts, namespaced or not, because that is how
 * xml-crypto finds a reference (`wsu:Id` on a WS-Trust element is one).
 */
export function assertUniqueIds(doc: Document): void {
  const seen = new Set<string>();
  const all = doc.getElementsByTagName('*') as unknown as ArrayLike<Element>;
  for (let i = 0; i < all.length; i += 1) {
    const el = all[i]!;
    for (let j = 0; j < el.attributes.length; j += 1) {
      const a = el.attributes[j]!;
      if (!ID_NAMES.has(a.localName ?? a.name) || !a.value) continue;
      if (seen.has(a.value)) throw new WsFedError('signature', `two elements carry the ID ${a.value}`);
      seen.add(a.value);
    }
  }
}

export function escapeXml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/** The PEM body of a certificate as one base64 line, the form metadata and KeyInfo carry. */
export function pemBody(pem: string): string {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, '').replace(/\s+/g, '');
}

/** A base64 certificate (as metadata carries it) as a PEM. */
export function toPem(base64: string): string {
  const body = base64.replace(/\s+/g, '');
  return `-----BEGIN CERTIFICATE-----\n${body.replace(/(.{64})/g, '$1\n').replace(/\n$/, '')}\n-----END CERTIFICATE-----\n`;
}

/**
 * The namespace and local name an `xsi:type` value names. The value is a QName whose prefix is resolved
 * against the namespaces in scope at `el`, so `fed:SecurityTokenServiceType` and
 * `x:SecurityTokenServiceType` are the same type when both prefixes are bound to the same namespace.
 */
export function xsiType(el: Element): { ns: string | null; local: string } | undefined {
  const value = el.getAttributeNS(NS.xsi, 'type');
  if (!value) return undefined;
  const colon = value.indexOf(':');
  const prefix = colon < 0 ? null : value.slice(0, colon).trim();
  const local = (colon < 0 ? value : value.slice(colon + 1)).trim();
  return { ns: el.lookupNamespaceURI(prefix), local };
}
