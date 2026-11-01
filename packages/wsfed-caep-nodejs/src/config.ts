// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The configuration: three settings are required (the realm, the reply URL and the identity provider's
// metadata); everything else the relying party needs is in that metadata. A WS-Federation sign-in request
// is not signed, so a key pair is optional: it is what an encrypted assertion is decrypted with, what the
// relying party's metadata publishes as its encryption key, and what the Shared Signals receiver can
// present as a TLS client certificate. `signals` defaults to on. `false` tells the application not to
// start that receiver. Sign-in does not read it. The relying party does not start a receiver by itself.

import { createPrivateKey, X509Certificate, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
import { WsFedError } from './errors.ts';

/**
 * The configuration, as a JSON file holds it. File paths are relative to the file.
 *
 * ```json
 * {
 *   "realm": "https://app.example.com/",
 *   "replyUrl": "https://app.example.com/wsfed",
 *   "idpMetadata": "https://idp.example.com/FederationMetadata/2007-06/FederationMetadata.xml"
 * }
 * ```
 */
export interface WsFedConfig {
  /** This relying party's realm: the `wtrealm` it sends, the audience its assertions must name, and its metadata's entityID. */
  realm: string;
  /** The reply URL (`wreply`): where the identity provider posts the sign-in response, and sends `wsignoutcleanup1.0`. */
  replyUrl: string;
  /** The identity provider's federation metadata: an http(s) URL, a file path, or the XML itself. */
  idpMetadata: string;

  /** The RSA private key encrypted assertions are decrypted with: a PEM file path, or the PEM. Required with `wantAssertionsEncrypted`. */
  privateKey?: string;
  /** The certificate for that key: a PEM file path, or the PEM. Published in the metadata as the encryption key. */
  certificate?: string;
  /** PEM certificate(s) to trust for TLS to the identity provider (the metadata URL), beyond node's own store: a file path or the PEM. */
  idpCa?: string;
  /** For metadata that is an aggregate: the identity provider's entityID. */
  idpEntityId?: string;
  /** How far the two clocks may disagree, in seconds. Default 60. */
  clockSkewSeconds?: number;
  /** Refuse an assertion that is not encrypted to this relying party's key. Default false. */
  wantAssertionsEncrypted?: boolean;
  /** Accept a sign-in response nobody asked for (identity-provider-initiated sign-in). Default false. */
  allowUnsolicited?: boolean;
  /**
   * Ask for a SAML 2.0 assertion with a `wreq` RequestSecurityToken naming its TokenType. Default true.
   * Turn it off only for an identity provider that refuses `wreq` and is configured to issue SAML 2.0 to
   * this realm by itself; the response is checked to hold a SAML 2.0 assertion either way.
   */
  requestTokenType?: boolean;
  /**
   * Receive CAEP and RISC. Default true. `false` turns them off: sign-in is unchanged, and the
   * application should not start a Shared Signals receiver or require transmitter metadata. The
   * relying party does not start a receiver by itself.
   */
  signals?: boolean;
}

/** The configuration with its files read and its defaults filled in. */
export interface ResolvedConfig {
  realm: string;
  replyUrl: string;
  idpMetadata: string;
  privateKey?: KeyObject;
  certificate?: X509Certificate;
  idpCa?: string;
  idpEntityId?: string;
  clockSkewMs: number;
  wantAssertionsEncrypted: boolean;
  allowUnsolicited: boolean;
  requestTokenType: boolean;
  /**
   * Present only when CAEP and RISC are off. Omitted when on (the default, and an explicit true),
   * so a configuration that leaves `signals` out still compares equal. Callers test `signals !== false`.
   */
  signals?: false;
}

const looksLikePem = (v: string) => v.includes('-----BEGIN ');

function material(value: string, baseDir: string, what: string): string {
  if (looksLikePem(value)) return value;
  const path = isAbsolute(value) ? value : resolve(baseDir, value);
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    throw new WsFedError('config', `${what} is neither a PEM nor a readable file (${path})`, { cause: err });
  }
}

function absoluteUrl(value: unknown, what: string): string {
  if (typeof value !== 'string' || !value.trim()) throw new WsFedError('config', `${what} is required`);
  try {
    const u = new URL(value);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('not http(s)');
  } catch {
    throw new WsFedError('config', `${what} must be an absolute http(s) URL, not ${value}`);
  }
  return value;
}

function flag(value: unknown, dflt: boolean, what: string): boolean {
  if (value === undefined || value === null) return dflt;
  if (typeof value !== 'boolean') throw new WsFedError('config', `${what} must be true or false`);
  return value;
}

/** Checks a configuration and reads its key, certificate and CA files, relative to `baseDir`. */
export function resolveConfig(config: WsFedConfig, baseDir = process.cwd()): ResolvedConfig {
  if (!config || typeof config !== 'object') throw new WsFedError('config', 'the configuration must be an object');
  const realm = config.realm;
  if (typeof realm !== 'string' || !realm.trim()) throw new WsFedError('config', 'realm is required');
  const replyUrl = absoluteUrl(config.replyUrl, 'replyUrl');
  if (typeof config.idpMetadata !== 'string' || !config.idpMetadata.trim()) throw new WsFedError('config', 'idpMetadata is required');
  let idpMetadata = config.idpMetadata.trim();
  if (!/^https?:\/\//.test(idpMetadata) && !idpMetadata.startsWith('<')) {
    idpMetadata = isAbsolute(idpMetadata) ? idpMetadata : resolve(baseDir, idpMetadata);
  }
  const skew = config.clockSkewSeconds ?? 60;
  if (typeof skew !== 'number' || !Number.isFinite(skew) || skew < 0 || skew > 600) {
    throw new WsFedError('config', 'clockSkewSeconds must be a number from 0 to 600');
  }
  const signals = flag(config.signals, true, 'signals');
  const out: ResolvedConfig = {
    realm,
    replyUrl,
    idpMetadata,
    clockSkewMs: skew * 1000,
    wantAssertionsEncrypted: flag(config.wantAssertionsEncrypted, false, 'wantAssertionsEncrypted'),
    allowUnsolicited: flag(config.allowUnsolicited, false, 'allowUnsolicited'),
    requestTokenType: flag(config.requestTokenType, true, 'requestTokenType'),
  };
  if (!signals) out.signals = false;

  if ((config.privateKey === undefined) !== (config.certificate === undefined)) {
    throw new WsFedError('config', 'privateKey and certificate go together: give both or neither');
  }
  if (config.privateKey !== undefined && config.certificate !== undefined) {
    let privateKey: KeyObject;
    let certificate: X509Certificate;
    try {
      privateKey = createPrivateKey(material(config.privateKey, baseDir, 'privateKey'));
      certificate = new X509Certificate(material(config.certificate, baseDir, 'certificate'));
    } catch (err) {
      if (err instanceof WsFedError) throw err;
      throw new WsFedError('config', `the private key or certificate cannot be read: ${(err as Error).message}`, { cause: err });
    }
    if (privateKey.asymmetricKeyType !== 'rsa') throw new WsFedError('config', `the private key is ${privateKey.asymmetricKeyType}; an RSA key is required`);
    if (!certificate.checkPrivateKey(privateKey)) throw new WsFedError('config', 'the certificate is not for the private key');
    out.privateKey = privateKey;
    out.certificate = certificate;
  } else if (out.wantAssertionsEncrypted) {
    throw new WsFedError('config', 'wantAssertionsEncrypted needs privateKey and certificate: the assertion is encrypted to them');
  }
  if (config.idpCa) out.idpCa = material(config.idpCa, baseDir, 'idpCa');
  if (config.idpEntityId) out.idpEntityId = config.idpEntityId;
  return out;
}

/** Reads a configuration file (JSON). Paths in it are relative to the file. `overrides` win over the file. */
export function readConfigFile(path: string, overrides: Partial<WsFedConfig> = {}): ResolvedConfig {
  let parsed: WsFedConfig;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as WsFedConfig;
  } catch (err) {
    throw new WsFedError('config', `${path} cannot be read as JSON: ${(err as Error).message}`, { cause: err });
  }
  const defined = Object.fromEntries(Object.entries(overrides).filter(([, v]) => v !== undefined));
  return resolveConfig({ ...parsed, ...defined }, dirname(resolve(path)));
}
