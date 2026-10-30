// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
//
// The smallest complete relying party, in plain JavaScript: node:http, no framework, no build step.
//
//   node examples/node-http.mjs wsfed.json
//
//   GET  /login    redirect to the identity provider (wsignin1.0)
//   POST /wsfed    the reply URL: the sign-in response arrives here
//   GET  /wsfed    the identity provider's sign-out cleanup (wsignoutcleanup1.0), loaded as an image
//   GET  /         who is signed in
//   POST /logout   sign out here, and at the identity provider (wsignout1.0)
//
// It keeps sessions in memory and signs its cookies with a per-process secret: enough to show every call
// the library needs, not a production session store. From CommonJS, `require('wsfed-caep-nodejs')`
// gives the same exports on Node 22.12 or later.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import http from 'node:http';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SECRET = randomBytes(32);
const sign = (v) => `${v}.${createHmac('sha256', SECRET).update(v).digest('base64url')}`;
function unsign(signed) {
  const dot = (signed ?? '').lastIndexOf('.');
  if (dot < 0) return undefined;
  const value = signed.slice(0, dot);
  const want = Buffer.from(sign(value));
  const got = Buffer.from(signed);
  return want.length === got.length && timingSafeEqual(want, got) ? value : undefined;
}
const cookies = (req) => Object.fromEntries((req.headers.cookie ?? '').split(';').map((c) => c.trim().split('=')).filter(([k, v]) => k && v));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const readBody = (req) => new Promise((resolve, reject) => {
  let text = '';
  req.setEncoding('utf8');
  req.on('data', (c) => { text += c; if (text.length > 512 * 1024) req.destroy(new Error('too large')); });
  req.on('end', () => resolve(text));
  req.on('error', reject);
});

/**
 * The application's request handler.
 * @param {import('wsfed-caep-nodejs').RelyingParty} rp
 * @returns {(req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>}
 */
export function createApp(rp) {
  /** @type {Map<string, import('wsfed-caep-nodejs').WsFedLogin>} */
  const sessions = new Map();
  const replyPath = new URL(rp.config.replyUrl).pathname;
  // Secure, unless the app runs on plain http (localhost), which browsers do not need it for.
  const secure = new URL(rp.config.replyUrl).protocol === 'https:' ? '; Secure' : '';
  // The cross-site POST from the identity provider drops a SameSite=Lax cookie, so the pending sign-in id
  // is SameSite=None, which a browser takes only with Secure (on http://localhost too), scoped to the reply URL.
  const pendingCookie = (v, age) => `wsfed_pending=${v}; Path=${replyPath}; HttpOnly; SameSite=None${secure || '; Secure'}; Max-Age=${age}`;

  return async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://app.invalid');
    const sid = unsign(cookies(req).sid);

    if (url.pathname === '/login' && req.method === 'GET') {
      const request = rp.login({ relayState: '/' });
      res.writeHead(302, { location: request.url, 'set-cookie': pendingCookie(sign(request.id), 600) });
      return void res.end();
    }

    if (url.pathname === replyPath && rp.isSignOutCleanup({ method: req.method ?? 'GET', url: req.url ?? '/' })) {
      if (sid) sessions.delete(sid);
      res.writeHead(200, { 'content-type': 'image/gif', 'set-cookie': `sid=; Path=/; HttpOnly; Max-Age=0${secure}` });
      return void res.end(Buffer.from('R0lGODlhAQABAAAAACH5BAEAAAAALAAAAAABAAEAAAI=', 'base64'));
    }

    if (url.pathname === replyPath && req.method === 'POST') {
      try {
        const who = await rp.handleReply(
          { method: 'POST', url: req.url ?? '/', body: await readBody(req) },
          { requestId: unsign(cookies(req).wsfed_pending) },
        );
        const id = randomBytes(24).toString('base64url');
        sessions.set(id, who);
        // Only ever a local path: relayState came back through the browser.
        const next = who.relayState?.startsWith('/') && !who.relayState.startsWith('//') ? who.relayState : '/';
        res.writeHead(303, { location: next, 'set-cookie': [pendingCookie('', 0), `sid=${sign(id)}; Path=/; HttpOnly; SameSite=Lax${secure}`] });
        return void res.end();
      } catch (err) {
        console.warn('sign-in refused:', err.code, err.message);
        res.writeHead(400, { 'content-type': 'text/plain' });
        return void res.end('Sign-in failed.');
      }
    }

    if (url.pathname === '/logout' && req.method === 'POST') {
      if (sid) sessions.delete(sid);
      res.writeHead(303, { location: rp.logout({ reply: new URL('/', rp.config.replyUrl).href }), 'set-cookie': `sid=; Path=/; HttpOnly; Max-Age=0${secure}` });
      return void res.end();
    }

    if (url.pathname === '/' && req.method === 'GET') {
      const who = sid ? sessions.get(sid) : undefined;
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      return void res.end(who
        ? `<p>Signed in as <strong>${esc(who.nameId)}</strong> by ${esc(who.issuer)}.</p><form method="post" action="/logout"><button>Sign out</button></form>`
        : '<p><a href="/login">Sign in with WS-Federation</a></p>');
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  };
}

// Run as a program: `node examples/node-http.mjs <config.json> [port]`.
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const { RelyingParty } = await import('wsfed-caep-nodejs');
  const rp = await RelyingParty.fromFile(process.argv[2] ?? 'wsfed.json');
  const port = Number(process.argv[3] ?? (new URL(rp.config.replyUrl).port || 3000));
  const app = createApp(rp);
  http.createServer((req, res) => {
    app(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  }).listen(port, () => console.log(`listening on ${port}; realm ${rp.config.realm}`));
}
