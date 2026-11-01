// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
/**
 * wsfed-caep-nodejs: a server-side WS-Federation relying party that accepts SAML 2.0 assertions, and a
 * CAEP and RISC receiver that ends its sessions. `"signals": false` turns the receiver off. The
 * relying party does not start one itself; the default is on. Sign-in does not change.
 *
 * ```ts
 * import { RelyingParty } from 'wsfed-caep-nodejs';
 *
 * const rp = await RelyingParty.fromFile('wsfed.json');
 * const request = rp.login({ relayState: '/' });   // keep request.id with the browser, then redirect to request.url
 * const who = await rp.handleReply({ method, url, body }, { requestId });   // at the reply URL
 * ```
 *
 * @packageDocumentation
 */

export { RelyingParty } from './relying-party.ts';
export type { LoginOptions, LoginRequest, RelyingPartyOptions, ReplyOptions, ReplyRequest } from './relying-party.ts';
export { readConfigFile, resolveConfig } from './config.ts';
export type { ResolvedConfig, WsFedConfig } from './config.ts';
export type { WsFedLogin } from './token.ts';
export type { IdpMetadata } from './metadata.ts';
export { MemoryReplayCache } from './replay.ts';
export type { ReplayCache } from './replay.ts';
export { WsFedError } from './errors.ts';
export type { WsFedErrorCode } from './errors.ts';
export { createSelfSignedKeyPair } from './x509.ts';
export type { KeyPair, KeyPairOptions } from './x509.ts';
export { SignalsReceiver } from './ssf/receiver.ts';
export type { SignalEvent, SignalsReceiverOptions } from './ssf/receiver.ts';
export { MemorySessionIndex, trackedFrom, DEFAULT_SUBJECT_ATTRIBUTE } from './ssf/session-index.ts';
export type { SessionIndex, TrackedSession } from './ssf/session-index.ts';
export { EVENT, CAEP_EVENTS, RISC_EVENTS, DEFAULT_EVENTS_REQUESTED, DEFAULT_ENDING_EVENTS, subjectOf } from './ssf/events.ts';
export type { SubjectRef } from './ssf/events.ts';
