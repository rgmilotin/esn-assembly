/**
 * Tests of the sign-in with ESN Accounts through OAuth 2.0; they cover the acceptance tests of
 * `ESNacc_OAUTH_INTEGRATION_SPEC.md` (ESN-Hungary/esnscope, section 10). Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { URL, URLSearchParams } from 'url';
import { verify } from 'jsonwebtoken';

import {
  ENDPOINT_AUTHORIZATION,
  ENDPOINT_TOKEN,
  ENDPOINT_USERINFO,
  getCookiePath,
  getRedirectUri
} from '../src/esnacc/config';
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
import { extractRoles } from '../src/esnacc/roles';
import { MissingLegacyIdError, mapUserInfoToUser, toLegacyRole, toLegacyRoles } from '../src/esnacc/userMapping';
import { OAuthRequestCookie, UserInfo } from '../src/esnacc/types';
import { ESNAccountsOAuthErrors } from '../src/models/esnaccOAuth.model';
import { User, UserRoles } from '../src/models/user.model';

const SECRET = 'test-platform-secret';
const REDIRECT_URI = getRedirectUri('api.assembly.esn.hu', 'dev');
const COOKIE_PATH = getCookiePath('dev');

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
      if (request.url === ENDPOINT_USERINFO) return responses.userinfo ?? json(200, { sub: '1', legacy_sub: 'jdoe' });
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

describe('configuration', () => {
  it('builds a fixed redirect URI per stage', () => {
    assert.equal(REDIRECT_URI, 'https://api.assembly.esn.hu/dev/esnacc_oauth_callback');
    assert.equal(
      getRedirectUri('api.assembly.esn.hu/', 'prod'),
      'https://api.assembly.esn.hu/prod/esnacc_oauth_callback'
    );
    assert.equal(COOKIE_PATH, '/dev/esnacc_oauth_callback');
  });
});

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
      userinfo: json(200, { sub: '1', legacy_sub: 'jdoe', future_claim: 42 })
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

describe('roles extraction', () => {
  it('reads the list of scoped roles returned by ESN Accounts', () => {
    assert.deepEqual(extractRoles({ groups: ['RO-TIMI-ESN:section-active_member', 'SEEP:member', 'no-scope'] }), [
      { role: 'section-active_member', source: 'groups', group: 'RO-TIMI-ESN', scope: 'RO-TIMI-ESN' },
      { role: 'member', source: 'groups', group: 'SEEP', scope: 'SEEP' },
      { role: 'no-scope', source: 'groups' }
    ]);
  });

  it('reads flat OAuth groups (spec test 8)', () => {
    assert.deepEqual(
      extractRoles({ groups: { '8': 'COMMITTEE:itcom-chair', '42': 'NATIONAL_ORGANISATION:president' } }),
      [
        { role: 'COMMITTEE:itcom-chair', source: 'groups', group: '8' },
        { role: 'NATIONAL_ORGANISATION:president', source: 'groups', group: '42' }
      ]
    );
  });

  it('reads detailed groups, with roles as an array or a single object (spec tests 9 and 10)', () => {
    const role = { role: 'COMMITTEE:itcom-chair', label: 'IT Committee Chair' };
    const group = { label: 'IT Committee', type: 'committee', scope: 'international' };
    const expected = [
      { ...role, source: 'detailed_groups', group: 'IT Committee', type: 'committee', scope: 'international' }
    ];
    assert.deepEqual(extractRoles({ detailed_groups: [{ ...group, roles: [role] }] }), expected);
    assert.deepEqual(extractRoles({ detailed_groups: [{ ...group, roles: role }] }), expected);
  });

  it('skips malformed entries and works without any role (spec test 11)', () => {
    assert.deepEqual(extractRoles({}), []);
    assert.deepEqual(
      extractRoles({ groups: { '1': 7 as any }, detailed_groups: [null, { roles: [{ role: 1 }] } as any] }),
      []
    );
  });
});

describe('user mapping', () => {
  it('maps a real-shaped profile to the same user that the CAS login produced', () => {
    assert.deepEqual(mapUserInfoToUser(REAL_SHAPED_USERINFO, extractRoles(REAL_SHAPED_USERINFO)), USER_FROM_CAS_LOGIN);
  });

  it('refuses profiles without a legacy (CAS) username', () => {
    assert.throws(() => mapUserInfoToUser({ sub: '123', preferred_username: 'jdoe' }, []), MissingLegacyIdError);
    assert.throws(() => mapUserInfoToUser({ sub: '123', legacy_sub: '  ' }, []), MissingLegacyIdError);
    assert.throws(() => mapUserInfoToUser({ sub: '123', legacy_sub: 42 as any }, []), /found: number/);
  });

  it('uses the lower-cased CAS username as user ID, like the CAS login', () => {
    assert.equal(mapUserInfoToUser({ legacy_sub: ' JDoe ' }, []).userId, 'jdoe');
    assert.equal(mapUserInfoToUser({ sub_legacy: 'JDoe' }, []).userId, 'jdoe', "ESNscope's name for the claim");
  });

  it('takes section, section code and country from the groups', () => {
    const user = mapUserInfoToUser(
      {
        legacy_sub: 'jdoe',
        detailed_groups: [
          { label: 'Central European Platform', type: 'Regional Platforms', scope: 'CEP', roles: [] },
          { label: 'ESN ELTE', type: 'section', scope: 'HU-BUDA-ELTE', roles: [] },
          { label: 'ESN Timisoara', type: 'section', scope: 'RO-TIMI-ESN', roles: [] }
        ]
      },
      []
    );
    assert.equal(user.sectionCode, 'HU-BUDA-ELTE', 'the first section');
    assert.equal(user.section, 'ESN ELTE');
    assert.equal(user.country, 'ESN Hungary', 'from the section code');

    const withCountryGroup = mapUserInfoToUser(
      {
        legacy_sub: 'jdoe',
        detailed_groups: [
          { label: 'ESN ELTE', type: 'section', scope: 'HU-BUDA-ELTE', roles: [] },
          { label: 'ESN Hungary (NO)', type: 'country', scope: 'HU', roles: [] }
        ]
      },
      []
    );
    assert.equal(withCountryGroup.country, 'ESN Hungary (NO)', "the country's group, when present");
  });

  it("doesn't crash on missing optional claims and always has a first name (spec test 11)", () => {
    const user = mapUserInfoToUser({ legacy_sub: 'jdoe', address: { country: 'Hungary' } }, []);
    assert.equal(user.firstName, 'jdoe');
    assert.equal(user.lastName, '');
    assert.equal(user.email, null);
    assert.equal(user.sectionCode, null);
    assert.equal(user.section, null);
    assert.equal(user.country, null, "the personal address' country is never used");
    assert.deepEqual(mapUserInfoToUser({ legacy_sub: 'jdoe', name: 'Jane Mary Doe' }, []), {
      ...user,
      firstName: 'Jane',
      lastName: 'Mary Doe'
    });
    assert.equal(mapUserInfoToUser({ legacy_sub: 'jdoe', email: 'jane@example.org' }, []).email, 'jane@example.org');
  });

  it('translates roles to the legacy (CAS) format', () => {
    const fromGroups = (role: string): string => toLegacyRole({ role, source: 'groups' });
    assert.equal(fromGroups('section-active_member'), 'Local.activeMember');
    assert.equal(fromGroups('section-regular_board_member'), 'Local.regularBoardMember');
    assert.equal(fromGroups('country-president'), 'National.president');
    assert.equal(fromGroups('all'), null, 'generic membership of a section');
    assert.equal(fromGroups('member'), null, 'membership of a regional platform');
    assert.equal(fromGroups('NATIONAL_ORGANISATION:president'), 'National.president');
    assert.equal(fromGroups('SECTION:regular-board-member'), 'Local.regularBoardMember');
    assert.equal(fromGroups('COMMITTEE:itcom-chair'), 'International.itcomChair');
    assert.equal(fromGroups('country-regular_board_member'), 'National.regularBoardMember');
    assert.equal(fromGroups('Local.activeMember:HU-BUPE-OBU'), 'Local.activeMember');
    assert.equal(fromGroups('International.ab.member'), 'International.ab.member');
    assert.equal(fromGroups('UNKNOWN_GROUP:president'), null);
    assert.equal(fromGroups('just-a-word'), null);
    assert.equal(
      toLegacyRole({ role: 'GROUP:chair', source: 'detailed_groups', type: 'committee', scope: 'international' }),
      'International.chair'
    );
    assert.deepEqual(
      toLegacyRoles([
        { role: 'SECTION:active-member', source: 'groups' },
        { role: 'SECTION:active_member', source: 'groups' }
      ]),
      ['Local.activeMember']
    );
  });

  it("produces roles that the platform's role rules recognise", () => {
    const userWith = (role: string): User =>
      new User({ userId: 'jdoe', roles: toLegacyRoles([{ role, source: 'groups' }]) });
    assert.ok(User.isAllowedBasedOnRoles(userWith('SECTION:regular-board-member'), [UserRoles.LOCAL_BOARD]));
    assert.ok(
      User.isAllowedBasedOnRoles(userWith('NATIONAL_ORGANISATION:regular_board_member'), [UserRoles.NATIONAL_BOARD])
    );
    assert.ok(User.isAllowedBasedOnRoles(userWith('NATIONAL_ORGANISATION:president'), [UserRoles.NATIONAL_LEVEL]));
    assert.ok(!User.isAllowedBasedOnRoles(userWith('SECTION:active-member'), [UserRoles.LOCAL_BOARD]));
  });
});
