// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The library from plain JavaScript: the example application (examples/node-http.mjs, no types, no
// build step) driven through a whole sign-in and sign-out over HTTP, against the stub identity provider.

import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, describe, it } from 'node:test';
import { createApp } from '../examples/node-http.mjs';
import { RelyingParty } from '../src/index.ts';
import { IDP_ENTITY, PASSIVE, RP_CERT, RP_KEY, idpMetadata, signedAssertion, wresult } from './stub-idp.ts';

describe('from JavaScript: the example application', () => {
  let server;
  let base;
  before(async () => {
    // The stub's assertion is for https://rp.test/, with that Recipient; the example serves it on 127.0.0.1.
    const rp = await RelyingParty.create({ realm: 'https://rp.test/', replyUrl: 'https://rp.test/wsfed', privateKey: RP_KEY, certificate: RP_CERT, idpMetadata: idpMetadata() });
    const app = createApp(rp);
    server = http.createServer((req, res) => { app(req, res).catch((e) => { res.writeHead(500); res.end(String(e)); }); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => new Promise((r) => server.close(r)));

  const cookieOf = (res, name) => res.headers.getSetCookie().map((c) => c.split(';')[0]).find((c) => c.startsWith(`${name}=`));

  it('signs in, shows who, honours the cleanup, and signs out at the identity provider', async () => {
    const login = await fetch(`${base}/login`, { redirect: 'manual' });
    assert.equal(login.status, 302);
    const to = new URL(login.headers.get('location'));
    assert.equal(to.origin + to.pathname, PASSIVE);
    const wctx = to.searchParams.get('wctx');
    const pending = cookieOf(login, 'wsfed_pending');
    assert.ok(pending, 'the pending sign-in cookie is set');

    // The identity provider's auto-posting form, as the browser submits it.
    const reply = await fetch(`${base}/wsfed`, {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: pending },
      body: new URLSearchParams({ wa: 'wsignin1.0', wresult: wresult({ token: signedAssertion().xml }), wctx }),
    });
    assert.equal(reply.status, 303, await reply.clone().text());
    const sid = cookieOf(reply, 'sid');
    const home = await (await fetch(`${base}/`, { headers: { cookie: sid } })).text();
    assert.match(home, /Signed in as <strong>alice-1234<\/strong>/);
    assert.match(home, new RegExp(IDP_ENTITY));

    const cleanup = await fetch(`${base}/wsfed?wa=wsignoutcleanup1.0`, { headers: { cookie: sid } });
    assert.equal(cleanup.headers.get('content-type'), 'image/gif');
    assert.match(await (await fetch(`${base}/`, { headers: { cookie: sid } })).text(), /Sign in with WS-Federation/);

    const out = await fetch(`${base}/logout`, { method: 'POST', redirect: 'manual' });
    assert.equal(new URL(out.headers.get('location')).searchParams.get('wa'), 'wsignout1.0');
  });

  it('refuses a response without the pending cookie', async () => {
    const res = await fetch(`${base}/wsfed`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ wa: 'wsignin1.0', wresult: wresult(), wctx: 'id=abc' }),
    });
    assert.equal(res.status, 400);
  });
});
