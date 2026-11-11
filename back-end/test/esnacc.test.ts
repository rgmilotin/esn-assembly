/**
 * Tests of the sign-in with ESN Accounts through OAuth 2.0; they cover the acceptance tests of
 * `ESNacc_OAUTH_INTEGRATION_SPEC.md` (ESN-Hungary/esnscope, section 10). Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { URL, URLSearchParams } from 'url';
import { verify } from 'jsonwebtoken';

import { ENDPOINT_AUTHORIZATION, ENDPOINT_TOKEN, ENDPOINT_USERINFO } from '../src/esnacc/config';
import { HttpClient, HttpRequest, HttpResponse } from '../src/esnacc/esnaccount';
import {
  OAuthFlowError,
  buildAuthorizationUrl,
  completeAuthorization,
  createCodeChallenge,
  expireOAuthCookie,
  getRequestCookies,
  parseOAuthCookie,
  randomValue,
  serializeOAuthCookie,
  timingSafeEqual
} from '../src/esnacc/oauth';
import { MissingUsernameError, mapUserInfoToUser } from '../src/esnacc/userMapping';
import { OAuthRequestCookie, UserInfo } from '../src/esnacc/types';
import { ESNAccountsOAuthErrors } from '../src/models/esnaccOAuth.model';
import { User, UserRoles } from '../src/models/user.model';

const SECRET = 'test-platform-secret';
const REDIRECT_URI = 'https://api.assembly.esn.hu/dev/esnacc_oauth_callback';
const COOKIE_PATH = '/dev/esnacc_oauth_callback';

//
// HELPERS
//

/**
 * A fake ESN Accounts: it records the requests and answers with the given responses.
 */
const fakeESNAccounts = (responses: { token?: HttpResponse; userinfo?: HttpResponse }) => {
  const requests: HttpRequest[] = [];
  const http: HttpClient = {
    request: async (request: HttpRequest): Promise<HttpResponse> => {
      requests.push(request);
      if (request.url === ENDPOINT_TOKEN)
        return responses.token ?? json(200, { access_token: 'ACCESS_TOKEN', token_type: 'Bearer' });
      if (request.url === ENDPOINT_USERINFO)
        return responses.userinfo ?? json(200, { sub: '1', preferred_username: 'jdoe' });
      return { status: 404, body: 'Not found' };
    }
  };
  return { http, requests };
};
const json = (status: number, body: unknown): HttpResponse => ({ status, body: JSON.stringify(body) });

const validCookie: OAuthRequestCookie = { state: 'STATE', codeVerifier: 'VERIFIER' };
const callback = (
  query: Record<string, string>,
  http: HttpClient,
  oauthCookie: OAuthRequestCookie | null = validCookie
): Promise<UserInfo> =>
  completeAuthorization({
    query,
    oauthCookie,
    clientId: 'CLIENT_ID',
    clientSecret: 'CLIENT_SECRET',
    redirectUri: REDIRECT_URI,
    http
  });

const rejectsWith = async (promise: Promise<unknown>, code: ESNAccountsOAuthErrors): Promise<OAuthFlowError> => {
  try {
    await promise;
  } catch (error) {
    assert.ok(error instanceof OAuthFlowError, 'expected an OAuthFlowError');
    assert.equal(error.code, code);
    return error;
  }
  assert.fail('expected the promise to reject');
};

//
// TESTS
//

describe('authorization request', () => {
  it('computes the PKCE challenge as base64url(SHA-256(verifier)) (RFC 7636, appendix B)', () => {
    assert.equal(
      createCodeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    );
  });

  it('generates random base64url values', () => {
    const state = randomValue();
    const verifier = randomValue(64);
    assert.match(state, /^[A-Za-z0-9_-]{43}$/);
    assert.match(verifier, /^[A-Za-z0-9_-]{86}$/);
    assert.notEqual(randomValue(), state);
  });

  it('sends scope, state, code_challenge and code_challenge_method=S256 (spec test 2)', () => {
    const url = new URL(
      buildAuthorizationUrl({
        clientId: 'CLIENT_ID',
        redirectUri: REDIRECT_URI,
        state: 'STATE',
        codeChallenge: 'CHALLENGE'
      })
    );
    assert.equal(url.origin.concat(url.pathname), ENDPOINT_AUTHORIZATION);
    assert.equal(url.searchParams.get('response_type'), 'code');
    assert.equal(url.searchParams.get('client_id'), 'CLIENT_ID');
    assert.equal(url.searchParams.get('redirect_uri'), REDIRECT_URI);
    assert.equal(url.searchParams.get('scope'), 'oauth2_access_to_profile_information');
    assert.equal(url.searchParams.get('state'), 'STATE');
    assert.equal(url.searchParams.get('code_challenge'), 'CHALLENGE');
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  });
});

describe('state cookie', () => {
  const now = Date.UTC(2026, 10, 2, 12, 0, 0);
  const setCookie = serializeOAuthCookie({ ...validCookie, localhostPort: 8100 }, SECRET, COOKIE_PATH, now);
  const cookieValue = setCookie.split(';')[0];

  it('is HttpOnly, Secure, SameSite=Lax, limited to the callback and short-lived', () => {
    assert.match(
      setCookie,
      /^esnacc_oauth=[^;]+; Max-Age=600; Path=\/dev\/esnacc_oauth_callback; HttpOnly; Secure; SameSite=Lax$/
    );
    assert.equal(
      expireOAuthCookie(COOKIE_PATH),
      'esnacc_oauth=; Max-Age=0; Path=/dev/esnacc_oauth_callback; HttpOnly; Secure; SameSite=Lax'
    );
  });

  it('round-trips state, verifier and localhost port', () => {
    assert.deepEqual(parseOAuthCookie(['other=1', cookieValue], SECRET, now), { ...validCookie, localhostPort: 8100 });
  });

  it('is rejected when missing, tampered with, signed with another secret or expired', () => {
    assert.equal(parseOAuthCookie(['other=1'], SECRET, now), null);
    const [payload, signature] = cookieValue.slice('esnacc_oauth='.length).split('.');
    const forgedPayload = Buffer.from(JSON.stringify({ state: 'X', codeVerifier: 'Y', exp: 9999999999 })).toString(
      'base64url'
    );
    assert.equal(parseOAuthCookie([`esnacc_oauth=${forgedPayload}.${signature}`], SECRET, now), null);
    assert.equal(parseOAuthCookie([`esnacc_oauth=${payload}.${signature.slice(1)}x`], SECRET, now), null);
    assert.equal(parseOAuthCookie([cookieValue], 'another-secret', now), null);
    assert.equal(parseOAuthCookie([cookieValue], SECRET, now + 601 * 1000), null);
    assert.equal(parseOAuthCookie(['esnacc_oauth=garbage'], SECRET, now), null);
  });

  it('can never be used as the platform API token', () => {
    assert.throws(() => verify(cookieValue.slice('esnacc_oauth='.length), SECRET));
  });

  it('is read from both API Gateway payload formats', () => {
    assert.deepEqual(getRequestCookies({ cookies: ['a=1', 'b=2'] }), ['a=1', 'b=2']);
    assert.deepEqual(
      getRequestCookies({ headers: { cookie: 'a=1; b=2' } }).map(x => x.trim()),
      ['a=1', 'b=2']
    );
    assert.deepEqual(getRequestCookies({ headers: {} }), []);
  });

  it('compares values in constant time', () => {
    assert.equal(timingSafeEqual('abc', 'abc'), true);
    assert.equal(timingSafeEqual('abc', 'abd'), false);
    assert.equal(timingSafeEqual('abc', 'abcd'), false);
  });
});

describe('callback', () => {
  it('reports the errors returned by ESN Accounts', async () => {
    const { http, requests } = fakeESNAccounts({});
    await rejectsWith(
      callback({ error: 'access_denied', error_description: 'User cancelled' }, http),
      ESNAccountsOAuthErrors.ACCESS_DENIED
    );
    await rejectsWith(callback({ error: 'server_error' }, http), ESNAccountsOAuthErrors.INVALID_REQUEST);
    assert.equal(requests.length, 0);
  });

  it('rejects a missing authorization code', async () => {
    const { http } = fakeESNAccounts({});
    await rejectsWith(callback({ state: 'STATE' }, http), ESNAccountsOAuthErrors.INVALID_REQUEST);
  });

  it('rejects a missing state cookie (spec test 3)', async () => {
    const { http, requests } = fakeESNAccounts({});
    await rejectsWith(callback({ code: 'CODE', state: 'STATE' }, http, null), ESNAccountsOAuthErrors.INVALID_STATE);
    assert.equal(requests.length, 0);
  });

  it('rejects a mismatched or missing state (spec test 4)', async () => {
    const { http, requests } = fakeESNAccounts({});
    await rejectsWith(callback({ code: 'CODE', state: 'OTHER' }, http), ESNAccountsOAuthErrors.INVALID_STATE);
    await rejectsWith(callback({ code: 'CODE' }, http), ESNAccountsOAuthErrors.INVALID_STATE);
    assert.equal(requests.length, 0);
  });

  it('exchanges the code with the same redirect URI and the original PKCE verifier (spec test 5)', async () => {
    const { http, requests } = fakeESNAccounts({});
    await callback({ code: 'CODE', state: 'STATE' }, http);

    const tokenRequest = requests[0];
    assert.equal(tokenRequest.method, 'POST');
    assert.equal(tokenRequest.url, ENDPOINT_TOKEN);
    assert.equal(tokenRequest.headers['Content-Type'], 'application/x-www-form-urlencoded');
    assert.equal(tokenRequest.headers.Accept, 'application/json');
    const form = new URLSearchParams(tokenRequest.body);
    assert.equal(form.get('grant_type'), 'authorization_code');
    assert.equal(form.get('code'), 'CODE');
    assert.equal(form.get('redirect_uri'), REDIRECT_URI);
    assert.equal(form.get('client_id'), 'CLIENT_ID');
    assert.equal(form.get('client_secret'), 'CLIENT_SECRET');
    assert.equal(form.get('code_verifier'), 'VERIFIER');
  });

  it('fails safely when the token response has no access_token, is not 2xx or is not JSON (spec test 6)', async () => {
    const cases: HttpResponse[] = [
      json(200, { token_type: 'Bearer' }),
      json(400, { error: 'invalid_grant' }),
      { status: 200, body: '<html>' }
    ];
    for (const token of cases) {
      const { http, requests } = fakeESNAccounts({ token });
      await rejectsWith(callback({ code: 'CODE', state: 'STATE' }, http), ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR);
      assert.equal(requests.length, 1, 'userinfo must not be requested');
    }
  });

  it('requests userinfo with the bearer access token (spec test 7) and returns it, unknown claims included (spec test 13)', async () => {
    const { http, requests } = fakeESNAccounts({
      userinfo: json(200, { sub: '1', preferred_username: 'jdoe', future_claim: 42 })
    });
    const userInfo = await callback({ code: 'CODE', state: 'STATE' }, http);

    assert.equal(requests[1].method, 'GET');
    assert.equal(requests[1].url, ENDPOINT_USERINFO);
    assert.equal(requests[1].headers.Authorization, 'Bearer ACCESS_TOKEN');
    assert.equal(userInfo.future_claim, 42);
  });

  it('fails safely when userinfo is not 2xx or not JSON, without exposing the access token (spec test 12)', async () => {
    for (const userinfo of [json(401, { error: 'invalid_token' }), { status: 200, body: 'not json' }]) {
      const { http } = fakeESNAccounts({ userinfo });
      const error = await rejectsWith(
        callback({ code: 'CODE', state: 'STATE' }, http),
        ESNAccountsOAuthErrors.ESN_ACCOUNTS_ERROR
      );
      assert.ok(!error.message.includes('ACCESS_TOKEN'));
    }
  });
});

/**
 * A userinfo with the same shape as a real one returned by ESN Accounts (an active member of two sections and of two
 * regional platforms), with made-up personal data; the CAS login produced, for the same person, the user below.
 */
const REAL_SHAPED_USERINFO: UserInfo = {
  sub: '6db5c0b5-0000-4000-8000-000000000000',
  name: 'Jane Doe',
  given_name: 'Jane',
  family_name: 'Doe',
  email: 'jane.personal@example.org',
  email_verified: true,
  picture: 'https://example.org/avatars/jane.jpg',
  esn_email: 'jane.doe@university.example.org',
  nickname: 'jdoe',
  preferred_username: 'jdoe',
  address: { cc: 'RO', country: 'Romania' },
  updated_at: 1792816646,
  nationality: 'RO',
  detailed_groups: [
    {
      label: 'ESN Timisoara',
      type: 'section',
      scope: 'RO-TIMI-ESN',
      roles: [
        { role: 'section-active_member', label: 'Active member' },
        { role: 'all', label: 'Member of a section of RO' },
        { role: 'all', label: 'Member of section RO-TIMI-ESN' }
      ]
    },
    {
      label: 'ESN Óbuda University',
      type: 'section',
      scope: 'HU-BUPE-OBU',
      roles: [
        { role: 'section-active_member', label: 'Active member' },
        { role: 'all', label: 'Member of a section of HU' },
        { role: 'all', label: 'Member of section HU-BUPE-OBU' }
      ]
    },
    {
      label: 'South Eastern European Platform',
      type: 'Regional Platforms',
      scope: 'SEEP',
      roles: { role: 'member', label: 'Member of SEEP' }
    },
    {
      label: 'Central European Platform',
      type: 'Regional Platforms',
      scope: 'CEP',
      roles: { role: 'member', label: 'Member of CEP' }
    }
  ],
  groups: [
    'RO-TIMI-ESN:section-active_member',
    'RO:all',
    'RO-TIMI-ESN:all',
    'HU-BUPE-OBU:section-active_member',
    'HU:all',
    'HU-BUPE-OBU:all',
    'SEEP:member',
    'CEP:member'
  ],
  legacy_sub: 'jdoe'
};
const USER_FROM_CAS_LOGIN = {
  userId: 'jdoe',
  email: 'jane.doe@university.example.org',
  firstName: 'Jane',
  lastName: 'Doe',
  roles: ['Local.activeMember'],
  sectionCode: 'RO-TIMI-ESN',
  section: 'ESN Timisoara',
  country: 'ESN Romania',
  avatarURL: 'https://example.org/avatars/jane.jpg'
};

describe('user mapping', () => {
  it('maps a real-shaped profile to the user that the CAS login produced, with the OAuth roles', () => {
    const user = mapUserInfoToUser(REAL_SHAPED_USERINFO);
    assert.deepEqual({ ...user, roles: USER_FROM_CAS_LOGIN.roles }, USER_FROM_CAS_LOGIN);
    assert.deepEqual(user.roles, REAL_SHAPED_USERINFO.groups);
  });

  it('gives the user the same permissions as the CAS login', () => {
    const oauthUser = new User(mapUserInfoToUser(REAL_SHAPED_USERINFO));
    const casUser = new User(USER_FROM_CAS_LOGIN);
    for (const role of Object.values(UserRoles))
      assert.equal(User.isAllowedBasedOnRoles(oauthUser, [role]), User.isAllowedBasedOnRoles(casUser, [role]), role);
  });

  it('uses the lower-cased username as user ID and refuses profiles without it', () => {
    assert.equal(mapUserInfoToUser({ preferred_username: ' JDoe ' }).userId, 'jdoe');
    assert.throws(() => mapUserInfoToUser({ sub: '123', legacy_sub: 'jdoe' }), MissingUsernameError);
    assert.throws(() => mapUserInfoToUser({ sub: '123', preferred_username: '  ' }), MissingUsernameError);
  });

  it('takes section and section code from the first section', () => {
    const user = mapUserInfoToUser({
      preferred_username: 'jdoe',
      detailed_groups: [
        { label: 'Central European Platform', type: 'Regional Platforms', scope: 'CEP', roles: [] },
        { label: 'ESN ELTE', type: 'section', scope: 'HU-BUDA-ELTE', roles: [] },
        { label: 'ESN Timisoara', type: 'section', scope: 'RO-TIMI-ESN', roles: [] }
      ]
    });
    assert.equal(user.sectionCode, 'HU-BUDA-ELTE');
    assert.equal(user.section, 'ESN ELTE');
    assert.equal(user.country, 'ESN Hungary');
  });

  it("doesn't crash on missing optional claims and always has a first name (spec test 11)", () => {
    const user = mapUserInfoToUser({ preferred_username: 'jdoe', address: { country: 'Hungary' } });
    assert.deepEqual(user, {
      userId: 'jdoe',
      email: null,
      firstName: 'jdoe',
      lastName: '',
      roles: [],
      sectionCode: null,
      section: null,
      country: null,
      avatarURL: null
    });
    assert.deepEqual(mapUserInfoToUser({ preferred_username: 'jdoe', name: 'Jane Mary Doe' }), {
      ...user,
      firstName: 'Jane',
      lastName: 'Mary Doe'
    });
    assert.equal(
      mapUserInfoToUser({ preferred_username: 'jdoe', email: 'jane@example.org' }).email,
      'jane@example.org'
    );
  });
});

describe('roles', () => {
  const allowed = (role: string, userRole: UserRoles): boolean =>
    User.isAllowedBasedOnRoles(new User({ userId: 'jdoe', roles: [role] }), [userRole]);

  it('recognises the OAuth roles of the "ESN Accounts - roles mapping" sheet', () => {
    assert.ok(allowed('HU-BUDA-ELTE:section-regular_board_member', UserRoles.LOCAL_BOARD));
    assert.ok(allowed('HU-BUDA-ELTE:section-active_member', UserRoles.LOCAL_LEVEL));
    assert.ok(!allowed('HU-BUDA-ELTE:section-active_member', UserRoles.LOCAL_BOARD));
    assert.ok(allowed('HU:country-regular_board_member', UserRoles.NATIONAL_BOARD));
    assert.ok(allowed('HU:country-president', UserRoles.NATIONAL_LEVEL));
    assert.ok(!allowed('HU:country-president', UserRoles.NATIONAL_BOARD));
    assert.ok(allowed('INT:international-vp_governance', UserRoles.INTERNATIONAL_BOARD));
    assert.ok(allowed('INT:international-staff', UserRoles.INTERNATIONAL_SECRETARIAT));
    assert.ok(allowed('BODY:ga-chair', UserRoles.INTERNATIONAL_GA_CT));
    assert.ok(allowed('BODY:ab-main_arbitrator', UserRoles.INTERNATIONAL_AB));
    assert.ok(allowed('BODY:ac', UserRoles.INTERNATIONAL_AC));
    assert.ok(allowed('COMMITTEE:itcom-chair', UserRoles.INTERNATIONAL_LEVEL));
    assert.ok(allowed('TEAM:eduk8-facilitator', UserRoles.INTERNATIONAL_LEVEL));
  });

  it("doesn't give permissions for generic memberships", () => {
    for (const role of ['HU:all', 'CEP:member', 'PERMISSIONS:it-wiki_admin'])
      assert.ok(
        Object.values(UserRoles).every(userRole => !allowed(role, userRole)),
        role
      );
  });

  it('still recognises the CAS roles', () => {
    assert.ok(allowed('Local.regularBoardMember', UserRoles.LOCAL_BOARD));
    assert.ok(allowed('Local.activeMember', UserRoles.LOCAL_LEVEL));
    assert.ok(allowed('National.president', UserRoles.NATIONAL_LEVEL));
    assert.ok(!allowed('National.president', UserRoles.NATIONAL_BOARD));
    assert.ok(allowed('International.AB.MainArbitrator', UserRoles.INTERNATIONAL_AB));
    assert.ok(allowed('International.vpGovernance', UserRoles.INTERNATIONAL_BOARD));
  });
});
