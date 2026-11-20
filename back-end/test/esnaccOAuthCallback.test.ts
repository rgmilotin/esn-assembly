/**
 * Tests of the callback of the sign-in with ESN Accounts through OAuth 2.0 and of the calls to ESN Accounts (with a
 * fake ESN Accounts). They cover the acceptance tests 3-7, 12 and 13 of `ESNacc_OAUTH_INTEGRATION_SPEC.md`.
 * Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { URLSearchParams } from 'url';

import { getESNAccountsEndpoints, getRedirectURI } from '../src/esnacc/config';
import { HttpClient, HttpRequest, HttpResponse } from '../src/esnacc/esnaccount';
import { OAuthFlowError, completeAuthorization } from '../src/esnacc/oauth';
import { OAuthRequestCookie, UserInfo } from '../src/esnacc/types';
import { ESNAccountsOAuthErrors } from '../src/models/esnaccOAuth.model';

const ENDPOINTS = getESNAccountsEndpoints('https://accounts.esn.org');
const REDIRECT_URI = getRedirectURI('api.assembly.esn.hu', 'dev');
const ACCESS_TOKEN = 'SECRET-ACCESS-TOKEN';
const CLIENT_SECRET = 'SECRET-CLIENT-SECRET';

//
// HELPERS
//

const json = (status: number, body: unknown): HttpResponse => ({ status, body: JSON.stringify(body) });

/**
 * A fake ESN Accounts: it records the requests and answers with the given responses.
 */
const fakeESNAccounts = (responses: { token?: HttpResponse; userinfo?: HttpResponse } = {}) => {
  const requests: HttpRequest[] = [];
  const http: HttpClient = {
    request: async (request: HttpRequest): Promise<HttpResponse> => {
      requests.push(request);
      if (request.url === ENDPOINTS.token)
        return responses.token ?? json(200, { access_token: ACCESS_TOKEN, token_type: 'Bearer' });
      if (request.url === ENDPOINTS.userinfo)
        return responses.userinfo ?? json(200, { sub: '1', preferred_username: 'jdoe' });
      return { status: 404, body: 'Not found' };
    }
  };
  return { http, requests };
};

const VALID_COOKIE: OAuthRequestCookie = { state: 'STATE', codeVerifier: 'VERIFIER' };
const VALID_QUERY = { code: 'CODE', state: 'STATE' };

const callback = (
  query: Record<string, string>,
  http: HttpClient,
  oauthCookie: OAuthRequestCookie | null = VALID_COOKIE
): Promise<UserInfo> =>
  completeAuthorization({
    query,
    oauthCookie,
    tokenEndpoint: ENDPOINTS.token,
    userinfoEndpoint: ENDPOINTS.userinfo,
    clientId: 'CLIENT_ID',
    clientSecret: CLIENT_SECRET,
    redirectURI: REDIRECT_URI,
    http
  });

const rejectsWith = async (promise: Promise<unknown>, code: ESNAccountsOAuthErrors): Promise<OAuthFlowError> => {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof OAuthFlowError, 'expected an OAuthFlowError');
    assert.equal(error.code, code);
    assert.ok(!error.message.includes(ACCESS_TOKEN), 'the error must not expose the access token');
    assert.ok(!error.message.includes(CLIENT_SECRET), 'the error must not expose the client secret');
    return error;
  }
  assert.fail('expected the promise to reject');
};

//
// TESTS
//

describe('callback: errors returned by ESN Accounts', () => {
  it('reports a cancelled/denied sign-in as access_denied, without calling ESN Accounts', async () => {
    const { http, requests } = fakeESNAccounts();
    await rejectsWith(callback({ error: 'access_denied' }, http), ESNAccountsOAuthErrors.ACCESS_DENIED);
    assert.equal(requests.length, 0);
  });
  it('reports any other provider error as invalid_request', async () => {
    const { http } = fakeESNAccounts();
    await rejectsWith(
      callback({ error: 'server_error', error_description: 'x' }, http),
      ESNAccountsOAuthErrors.INVALID_REQUEST
    );
  });
  it("doesn't copy arbitrary text from the provider's error into the logs", async () => {
    const { http } = fakeESNAccounts();
    const error = await rejectsWith(
      callback({ error: 'bad\n<script>error' }, http),
      ESNAccountsOAuthErrors.INVALID_REQUEST
    );
    assert.ok(!/[\n<>]/.test(error.message));
  });
  it('rejects a missing authorization code', async () => {
    const { http, requests } = fakeESNAccounts();
    await rejectsWith(callback({ state: 'STATE' }, http), ESNAccountsOAuthErrors.INVALID_REQUEST);
    assert.equal(requests.length, 0);
  });
});

describe('callback: state', () => {
  it('rejects a missing (or expired, or tampered) state cookie (spec test 3)', async () => {
    const { http, requests } = fakeESNAccounts();
    await rejectsWith(callback(VALID_QUERY, http, null), ESNAccountsOAuthErrors.INVALID_STATE);
    assert.equal(requests.length, 0);
  });
  it('rejects a mismatched or missing state (spec test 4)', async () => {
    const { http, requests } = fakeESNAccounts();
    await rejectsWith(callback({ code: 'CODE', state: 'OTHER' }, http), ESNAccountsOAuthErrors.INVALID_STATE);
    await rejectsWith(callback({ code: 'CODE' }, http), ESNAccountsOAuthErrors.INVALID_STATE);
    assert.equal(requests.length, 0);
  });
});

describe('callback: token exchange', () => {
  it('sends the same redirect URI and the original PKCE verifier (spec test 5)', async () => {
    const { http, requests } = fakeESNAccounts();
    await callback(VALID_QUERY, http);

    const tokenRequest = requests[0];
    assert.equal(tokenRequest.method, 'POST');
    assert.equal(tokenRequest.url, 'https://accounts.esn.org/oauth/token');
    assert.equal(tokenRequest.headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(tokenRequest.headers.Accept, 'application/json');
    assert.deepEqual(Object.fromEntries(new URLSearchParams(tokenRequest.body)), {
      grant_type: 'authorization_code',
      code: 'CODE',
      redirect_uri: 'https://api.assembly.esn.hu/dev/esnacc_oauth_callback',
      client_id: 'CLIENT_ID',
      client_secret: CLIENT_SECRET,
      code_verifier: 'VERIFIER'
    });
  });
  it('fails safely when the response has no access_token, is not 2xx or is not JSON (spec test 6)', async () => {
    const failures: HttpResponse[] = [
      json(200, { token_type: 'Bearer' }),
      json(200, { access_token: 42 }),
      json(400, { error: 'invalid_grant' }),
      json(500, { error: 'server_error', client_secret: CLIENT_SECRET }),
      { status: 200, body: 'not JSON' },
      json(200, ['not', 'an', 'object'])
    ];
    for (const token of failures) {
      const { http, requests } = fakeESNAccounts({ token });
      await rejectsWith(callback(VALID_QUERY, http), ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR);
      assert.equal(requests.length, 1, 'userinfo must not be requested');
    }
  });
  it('reports only the OAuth error code of a failed response', async () => {
    const { http } = fakeESNAccounts({ token: json(400, { error: 'invalid_grant', error_description: 'secret?' }) });
    const error = await rejectsWith(callback(VALID_QUERY, http), ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR);
    assert.equal(error.message, 'Token endpoint returned HTTP 400 (invalid_grant)');
  });
  it('reports a network failure as an ESN Accounts error', async () => {
    const http: HttpClient = { request: async () => Promise.reject(new Error('timeout of 10000ms exceeded')) };
    await rejectsWith(callback(VALID_QUERY, http), ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR);
  });
});

describe('callback: userinfo', () => {
  it('is requested with the bearer access token (spec test 7) and returned with unknown claims (spec test 13)', async () => {
    const userinfo = { sub: '1', preferred_username: 'jdoe', a_future_claim: { x: 1 } };
    const { http, requests } = fakeESNAccounts({ userinfo: json(200, userinfo) });

    const result = await callback(VALID_QUERY, http);

    const userinfoRequest = requests[1];
    assert.equal(userinfoRequest.method, 'GET');
    assert.equal(userinfoRequest.url, 'https://accounts.esn.org/oauth/v2/userinfo');
    assert.equal(userinfoRequest.headers.Authorization, `Bearer ${ACCESS_TOKEN}`);
    assert.deepEqual(result, userinfo);
  });
  it('fails safely when not 2xx or not JSON, without exposing the access token (spec test 12)', async () => {
    const failures: HttpResponse[] = [
      json(401, { error: 'invalid_token' }),
      json(500, { echo: ACCESS_TOKEN }),
      { status: 200, body: `<html>${ACCESS_TOKEN}</html>` }
    ];
    for (const userinfo of failures) {
      const { http } = fakeESNAccounts({ userinfo });
      await rejectsWith(callback(VALID_QUERY, http), ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR);
    }
  });
});
