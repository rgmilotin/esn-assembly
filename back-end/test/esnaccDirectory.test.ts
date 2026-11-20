/**
 * Tests of the directory of ESN Accounts' sections and countries (lookup, cache and fallback), with a fake ESN
 * Accounts. Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import { getESNAccountsEndpoints } from '../src/esnacc/config';
import { HttpClient, HttpRequest, HttpResponse } from '../src/esnacc/esnaccount';
import {
  DIRECTORY_CACHE_TTL_MS,
  DIRECTORY_REQUEST_TIMEOUT_MS,
  DIRECTORY_RETRY_AFTER_MS,
  ESNDirectory,
  createDirectoryLoader,
  parseDirectory,
  resolveSectionAndCountry
} from '../src/esnacc/directory';
import { MappedUserData } from '../src/esnacc/userMapping';

const ENDPOINTS = getESNAccountsEndpoints('https://accounts.esn.org');

/**
 * Entries with the same shape as the real ones (only the fields used, plus a few others).
 */
const SECTIONS = [
  { label: 'ESN ELTE', code: 'HU-BUPE-ELT', country: 'Hungary', cc: 'HU', state: 'active', email: 'x@example.org' },
  { label: 'ESN Óbuda University', code: 'HU-BUPE-OBU', country: 'Hungary', cc: 'HU', state: 'active' },
  { label: 'ESN Timisoara', code: 'RO-TIMI-ESN', country: 'Romania', cc: 'RO', state: 'active' }
];
const COUNTRIES = [
  { label: 'ESN Hungary', code: 'HU', cc: 'HU', country: 'Hungary', state: 'active' },
  { label: 'ESN Romania', code: 'RO', cc: 'RO', country: 'Romania', state: 'active' }
];

const json = (status: number, body: unknown): HttpResponse => ({ status, body: JSON.stringify(body) });

/**
 * A fake ESN Accounts whose answers can change over time.
 */
const fakeESNAccounts = () => {
  const requests: HttpRequest[] = [];
  const state = { sections: json(200, SECTIONS), countries: json(200, COUNTRIES), fail: false };
  const http: HttpClient = {
    request: async (request: HttpRequest): Promise<HttpResponse> => {
      requests.push(request);
      if (state.fail) throw new Error('timeout of 3000ms exceeded');
      if (request.url === ENDPOINTS.sections) return state.sections;
      if (request.url === ENDPOINTS.countries) return state.countries;
      return { status: 404, body: 'Not found' };
    }
  };
  return { http, requests, state };
};

const clock = (start = Date.UTC(2026, 0, 1)) => {
  const c = { time: start, now: (): number => c.time };
  return c;
};

const loaderFor = (http: HttpClient, now: () => number, errors: Error[] = []) =>
  createDirectoryLoader({
    sectionsEndpoint: ENDPOINTS.sections,
    countriesEndpoint: ENDPOINTS.countries,
    http,
    now,
    onError: error => errors.push(error)
  });

const user = (data: Partial<MappedUserData>): MappedUserData => ({
  userId: 'jdoe',
  email: null,
  firstName: 'Jane',
  lastName: 'Doe',
  roles: [],
  sectionCode: null,
  section: null,
  country: null,
  avatarURL: null,
  ...data
});

const DIRECTORY: ESNDirectory = parseDirectory(SECTIONS, COUNTRIES);

describe('directory: parsing', () => {
  it('indexes sections and countries by upper-cased code', () => {
    assert.deepEqual(DIRECTORY.sections.get('HU-BUPE-ELT'), { label: 'ESN ELTE', countryCode: 'HU' });
    assert.equal(DIRECTORY.countries.get('RO'), 'ESN Romania');
    assert.equal(
      parseDirectory([{ code: 'hu-x-y', label: 'X', cc: 'hu' }], COUNTRIES).sections.get('HU-X-Y').label,
      'X'
    );
  });
  it('skips malformed entries', () => {
    const directory = parseDirectory(
      [null, 'x', { code: 'A-B-C' }, { label: 'No code' }, ...SECTIONS],
      [{}, ...COUNTRIES]
    );
    assert.equal(directory.sections.size, SECTIONS.length);
    assert.equal(directory.countries.size, COUNTRIES.length);
  });
  it('refuses an empty directory', () => {
    assert.throws(() => parseDirectory([], COUNTRIES));
    assert.throws(() => parseDirectory(SECTIONS, [{ foo: 'bar' }]));
  });
});

describe('directory: section and country of the user', () => {
  it('names section and country as the CAS login did', () => {
    const resolved = resolveSectionAndCountry(
      user({ sectionCode: 'HU-BUPE-OBU', section: 'from userinfo' }),
      DIRECTORY
    );
    assert.equal(resolved.section, 'ESN Óbuda University');
    assert.equal(resolved.country, 'ESN Hungary');
  });
  it('takes the country of users without a section from their country roles, then from their memberships', () => {
    assert.equal(
      resolveSectionAndCountry(user({ roles: ['CEP:member', 'RO:country-president'] }), DIRECTORY).country,
      'ESN Romania'
    );
    assert.equal(resolveSectionAndCountry(user({ roles: ['CEP:member', 'hu:all'] }), DIRECTORY).country, 'ESN Hungary');
    assert.equal(resolveSectionAndCountry(user({ roles: ['INT:international-staff'] }), DIRECTORY).country, null);
  });
  it('keeps the data of the userinfo for sections unknown to the directory', () => {
    const resolved = resolveSectionAndCountry(
      user({ sectionCode: 'XX-UNKN-OWN', section: 'ESN Unknown', roles: ['RO:all'] }),
      DIRECTORY
    );
    assert.equal(resolved.section, 'ESN Unknown');
    assert.equal(resolved.country, 'ESN Romania');
  });
  it('without a directory, keeps the data of the userinfo and has no country', () => {
    const original = user({ sectionCode: 'HU-BUPE-ELT', section: 'ESN ELTE (userinfo)' });
    const resolved = resolveSectionAndCountry(original, null);
    assert.deepEqual(resolved, original);
    assert.notEqual(resolved, original);
  });
  it("doesn't change the other fields", () => {
    const original = user({ sectionCode: 'HU-BUPE-ELT', roles: ['HU-BUPE-ELT:section-president'] });
    const { section, country, ...rest } = resolveSectionAndCountry(original, DIRECTORY);
    assert.deepEqual({ ...rest, section, country }, { ...original, section: 'ESN ELTE', country: 'ESN Hungary' });
  });
});

describe('directory: loading and cache', () => {
  it('loads both lists from ESN Accounts, with a short timeout', async () => {
    const { http, requests } = fakeESNAccounts();
    const directory = await loaderFor(http, clock().now).load();
    assert.equal(directory.sections.size, 3);
    assert.deepEqual(requests.map(r => r.url).sort(), [ENDPOINTS.countries, ENDPOINTS.sections]);
    assert.ok(requests.every(r => r.method === 'GET' && r.timeoutMs === DIRECTORY_REQUEST_TIMEOUT_MS));
  });
  it('is cached for the TTL, then reloaded', async () => {
    const { http, requests } = fakeESNAccounts();
    const c = clock();
    const loader = loaderFor(http, c.now);
    await loader.load();
    c.time += DIRECTORY_CACHE_TTL_MS - 1;
    await loader.load();
    assert.equal(requests.length, 2);
    c.time += 1;
    await loader.load();
    assert.equal(requests.length, 4);
  });
  it('shares one load between concurrent sign-ins', async () => {
    const { http, requests } = fakeESNAccounts();
    const loader = loaderFor(http, clock().now);
    const [a, b] = await Promise.all([loader.load(), loader.load()]);
    assert.equal(a, b);
    assert.equal(requests.length, 2);
  });
});

describe('directory: ESN Accounts unavailable', () => {
  it('without a previous load, returns null (never throws) and reports the error', async () => {
    const { http, state } = fakeESNAccounts();
    state.fail = true;
    const errors: Error[] = [];
    assert.equal(await loaderFor(http, clock().now, errors).load(), null);
    assert.equal(errors.length, 1);
  });
  it('fails on non-2xx, invalid JSON, non-list or empty answers', async () => {
    const failures: Partial<{ sections: HttpResponse; countries: HttpResponse }>[] = [
      { sections: json(503, {}) },
      { countries: { status: 200, body: '<html>' } },
      { sections: json(200, { not: 'a list' }) },
      { sections: json(200, []) }
    ];
    for (const failure of failures) {
      const { http, state } = fakeESNAccounts();
      Object.assign(state, failure);
      assert.equal(await loaderFor(http, clock().now).load(), null);
    }
  });
  it('keeps using the last loaded directory, even after the TTL', async () => {
    const { http, state } = fakeESNAccounts();
    const c = clock();
    const errors: Error[] = [];
    const loader = loaderFor(http, c.now, errors);
    const first = await loader.load();
    state.fail = true;
    c.time += DIRECTORY_CACHE_TTL_MS + 1;
    assert.equal(await loader.load(), first);
    assert.equal(errors.length, 1);
  });
  it("doesn't retry before a while, so that an outage doesn't slow down every sign-in", async () => {
    const { http, requests, state } = fakeESNAccounts();
    const c = clock();
    const loader = loaderFor(http, c.now);
    state.fail = true;
    await loader.load();
    const attempts = requests.length;
    c.time += DIRECTORY_RETRY_AFTER_MS - 1;
    assert.equal(await loader.load(), null);
    assert.equal(requests.length, attempts);
    state.fail = false;
    c.time += 1;
    assert.equal((await loader.load()).countries.get('HU'), 'ESN Hungary');
  });
});
