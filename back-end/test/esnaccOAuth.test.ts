/**
 * Tests of the PKCE, `state` and flow-cookie helpers of the sign-in with ESN Accounts through OAuth 2.0.
 * They cover the related acceptance tests of `ESNacc_OAUTH_INTEGRATION_SPEC.md` (ESN-Hungary/esnscope, section 10).
 * Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { URL } from 'url';
import { sign, verify } from 'jsonwebtoken';

import { CALLBACK_PATH, OAUTH_COOKIE_NAME, getESNAccountsEndpoints, getRedirectURI } from '../src/esnacc/config';
import {
  buildAuthorizationURL,
  createCodeChallenge,
  createCodeVerifier,
  expireOAuthCookie,
  getRequestCookies,
  parseOAuthCookie,
  randomValue,
  serializeOAuthCookie,
  timingSafeEqual
} from '../src/esnacc/oauth';
import { OAuthRequestCookie } from '../src/esnacc/types';

const SECRET = 'test-platform-secret';
const ENDPOINTS = getESNAccountsEndpoints('https://accounts.esn.org');
const REDIRECT_URI = getRedirectURI('api.assembly.esn.hu', 'dev');
const COOKIE_PATH = '/dev'.concat(CALLBACK_PATH);
const BASE64URL = /^[A-Za-z0-9_-]+$/;

describe('configuration', () => {
  it('derives every ESN Accounts endpoint from the base URL', () => {
    assert.deepEqual(getESNAccountsEndpoints('https://accounts.esn.org/'), {
      authorization: 'https://accounts.esn.org/oauth/authorize',
      token: 'https://accounts.esn.org/oauth/token',
      userinfo: 'https://accounts.esn.org/oauth/v2/userinfo',
      countries: 'https://accounts.esn.org/api/v2/countries',
      sections: 'https://accounts.esn.org/api/v2/sections'
    });
  });
  it('derives the redirect URI from the API domain and the stage', () => {
    assert.equal(REDIRECT_URI, 'https://api.assembly.esn.hu/dev/esnacc_oauth_callback');
  });
  it('refuses a missing configuration', () => {
    assert.throws(() => getESNAccountsEndpoints(undefined));
    assert.throws(() => getRedirectURI(undefined, 'dev'));
    assert.throws(() => getRedirectURI('api.assembly.esn.hu', undefined));
  });
});

describe('PKCE and state', () => {
  it('computes the challenge as base64url(SHA-256(verifier)) (RFC 7636, appendix B)', () => {
    assert.equal(
      createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    );
  });
  it('generates a verifier of 64 random bytes, within the RFC 7636 length', () => {
    const verifier = createCodeVerifier();
    assert.equal(verifier.length, 86);
    assert.match(verifier, BASE64URL);
    assert.notEqual(verifier, createCodeVerifier());
  });
  it('generates random, unpadded base64url values for the state', () => {
    const values = new Set(Array.from({ length: 50 }, () => randomValue()));
    assert.equal(values.size, 50);
    for (const value of values) {
      assert.equal(value.length, 43);
      assert.match(value, BASE64URL);
    }
  });
  it('compares values in constant time, refusing different lengths and non-strings', () => {
    assert.equal(timingSafeEqual('abc', 'abc'), true);
    assert.equal(timingSafeEqual('abc', 'abd'), false);
    assert.equal(timingSafeEqual('abc', 'abcd'), false);
    assert.equal(timingSafeEqual(undefined, 'abc'), false);
  });
});

describe('authorization request', () => {
  it('sends scope, state, code_challenge and code_challenge_method=S256 (spec test 2)', () => {
    const url = new URL(
      buildAuthorizationURL({
        authorizationEndpoint: ENDPOINTS.authorization,
        clientId: 'CLIENT ID',
        redirectURI: REDIRECT_URI,
        state: 'STATE',
        codeChallenge: 'CHALLENGE'
      })
    );
    assert.equal(url.origin.concat(url.pathname), 'https://accounts.esn.org/oauth/authorize');
    assert.deepEqual(Object.fromEntries(url.searchParams), {
      response_type: 'code',
      client_id: 'CLIENT ID',
      redirect_uri: REDIRECT_URI,
      scope: 'oauth2_access_to_profile_information',
      state: 'STATE',
      code_challenge: 'CHALLENGE',
      code_challenge_method: 'S256'
    });
  });
  it('URL-encodes the values', () => {
    const url = buildAuthorizationURL({
      authorizationEndpoint: ENDPOINTS.authorization,
      clientId: 'a&b=c',
      redirectURI: REDIRECT_URI,
      state: 'S',
      codeChallenge: 'C'
    });
    assert.ok(url.includes('client_id=a%26b%3Dc'));
    assert.ok(url.includes('redirect_uri=https%3A%2F%2Fapi.assembly.esn.hu%2Fdev%2Fesnacc_oauth_callback'));
  });
});

describe('flow cookie', () => {
  const flow: OAuthRequestCookie = { state: 'STATE', codeVerifier: 'VERIFIER', localhostPort: 8100 };
  const NOW = Date.UTC(2026, 0, 1);
  const setCookie = serializeOAuthCookie(flow, SECRET, COOKIE_PATH, NOW);
  const cookieValue = setCookie.split(';')[0];

  it('is HttpOnly, Secure, SameSite=Lax, limited to the callback and short-lived (10 minutes)', () => {
    const attributes = setCookie.split(';').map(part => part.trim());
    assert.ok(cookieValue.startsWith(OAUTH_COOKIE_NAME.concat('=')));
    assert.ok(attributes.includes('Max-Age=600'));
    assert.ok(attributes.includes('Path=/dev/esnacc_oauth_callback'));
    assert.ok(attributes.includes('HttpOnly'));
    assert.ok(attributes.includes('Secure'));
    assert.ok(attributes.includes('SameSite=Lax'));
  });
  it('round-trips state, verifier and localhost port', () => {
    assert.deepEqual(parseOAuthCookie([cookieValue], SECRET, NOW), flow);
    assert.deepEqual(parseOAuthCookie(['other=1', ` ${cookieValue}`], SECRET, NOW), flow);
  });
  it('is rejected when missing, tampered with, signed with another secret, malformed or expired', () => {
    const [payload, signature] = cookieValue.slice(OAUTH_COOKIE_NAME.length + 1).split('.');
    const forged = Buffer.from(JSON.stringify({ state: 'X', codeVerifier: 'Y', exp: 9999999999 })).toString(
      'base64url'
    );
    assert.equal(parseOAuthCookie([], SECRET, NOW), null);
    assert.equal(parseOAuthCookie([`${OAUTH_COOKIE_NAME}=${forged}.${signature}`], SECRET, NOW), null);
    assert.equal(parseOAuthCookie([`${OAUTH_COOKIE_NAME}=${payload}.${signature}x`], SECRET, NOW), null);
    assert.equal(parseOAuthCookie([`${OAUTH_COOKIE_NAME}=${payload}`], SECRET, NOW), null);
    assert.equal(parseOAuthCookie([`${OAUTH_COOKIE_NAME}=${payload}.${signature}.x`], SECRET, NOW), null);
    assert.equal(parseOAuthCookie([cookieValue], 'another-secret', NOW), null);
    assert.equal(parseOAuthCookie([cookieValue], SECRET, NOW + 601 * 1000), null);
  });
  it('can never be used as the platform API token, nor a token as the cookie', () => {
    assert.throws(() => verify(cookieValue.slice(OAUTH_COOKIE_NAME.length + 1), SECRET));
    const token = sign({ state: 'STATE', codeVerifier: 'VERIFIER' }, SECRET);
    assert.equal(parseOAuthCookie([`${OAUTH_COOKIE_NAME}=${token}`], SECRET), null);
  });
  it('is deleted with the same attributes', () => {
    assert.equal(
      expireOAuthCookie(COOKIE_PATH),
      'esnacc_oauth=; Max-Age=0; Path=/dev/esnacc_oauth_callback; HttpOnly; Secure; SameSite=Lax'
    );
  });
  it('is read from both API Gateway payload formats', () => {
    assert.deepEqual(getRequestCookies({ cookies: ['a=1', 'b=2'] }), ['a=1', 'b=2']);
    assert.deepEqual(getRequestCookies({ headers: { cookie: 'a=1; b=2' } }), ['a=1', ' b=2']);
    assert.deepEqual(getRequestCookies({ headers: { Cookie: 'a=1' } }), ['a=1']);
    assert.deepEqual(getRequestCookies({}), []);
  });
});
