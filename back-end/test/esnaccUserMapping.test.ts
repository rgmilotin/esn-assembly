/**
 * Tests of the mapping of the ESN Accounts userinfo (OAuth 2.0) to the platform's user. Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import { MissingUsernameError, getRoles, getUserId, mapUserInfoToUser } from '../src/esnacc/userMapping';
import { UserInfo } from '../src/esnacc/types';

/**
 * A userinfo with the same shape as a real one returned by ESN Accounts (an active member of two sections and of two
 * regional platforms), with made-up personal data.
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
  preferred_username: 'JDoe',
  address: { cc: 'RO', country: 'Romania' },
  updated_at: 1792816646,
  detailed_groups: [
    {
      label: 'ESN Timisoara',
      type: 'section',
      scope: 'RO-TIMI-ESN',
      roles: [
        { role: 'section-active_member', label: 'Active member' },
        { role: 'all', label: 'Member of a section of RO' }
      ]
    },
    {
      label: 'ESN Óbuda University',
      type: 'section',
      scope: 'HU-BUPE-OBU',
      roles: [{ role: 'section-regular_board_member', label: 'Board member' }]
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
    'HU-BUPE-OBU:section-regular_board_member',
    'HU:all',
    'CEP:member'
  ],
  legacy_sub: 'someone-else'
};

describe('user mapping', () => {
  it('maps a real-shaped profile to the same fields that the CAS login produces', () => {
    assert.deepEqual(mapUserInfoToUser(REAL_SHAPED_USERINFO), {
      userId: 'jdoe',
      email: 'jane.doe@university.example.org',
      firstName: 'Jane',
      lastName: 'Doe',
      roles: [
        'RO-TIMI-ESN:section-active_member',
        'RO:all',
        'RO-TIMI-ESN:all',
        'HU-BUPE-OBU:section-regular_board_member',
        'HU:all',
        'CEP:member'
      ],
      sectionCode: 'RO-TIMI-ESN',
      section: 'ESN Timisoara',
      country: null,
      avatarURL: 'https://example.org/avatars/jane.jpg'
    });
  });
  it('falls back to `email` when there is no ESN email', () => {
    const { email } = mapUserInfoToUser({ ...REAL_SHAPED_USERINFO, esn_email: '  ' });
    assert.equal(email, 'jane.personal@example.org');
  });
});

describe('user ID (preferred_username)', () => {
  it('is the lower-cased username, as the CAS login does with the CAS username', () => {
    assert.equal(getUserId({ preferred_username: 'Jane.Doe' }), 'jane.doe');
    assert.equal(getUserId({ preferred_username: ' jdoe ' }), 'jdoe');
    assert.equal(getUserId({ preferred_username: 'jane doe' }), 'jane doe');
  });
  it('never uses `sub` or the legacy identifiers', () => {
    assert.throws(
      () => getUserId({ sub: 'uuid', sub_legacy: 'jdoe', legacy_sub: 'jdoe', nickname: 'jdoe' }),
      MissingUsernameError
    );
  });
  it('refuses a missing, empty or non-string username', () => {
    for (const preferred_username of [undefined, null, '', '   ', 42, ['jdoe']] as any[])
      assert.throws(() => mapUserInfoToUser({ preferred_username }), MissingUsernameError);
  });
  it('refuses a username that ESN Accounts could not have issued', () => {
    assert.throws(() => getUserId({ preferred_username: 'a'.repeat(61) }), MissingUsernameError);
    assert.throws(() => getUserId({ preferred_username: 'jane\ndoe' }), MissingUsernameError);
    assert.equal(getUserId({ preferred_username: 'a'.repeat(60) }), 'a'.repeat(60));
  });
});

describe('roles (groups)', () => {
  it('reads the array format', () => {
    assert.deepEqual(getRoles({ groups: ['HU:all', 'HU-BUPE-ELT:section-president'] }), [
      'HU:all',
      'HU-BUPE-ELT:section-president'
    ]);
  });
  it("reads the spec's object format (spec test 8)", () => {
    assert.deepEqual(getRoles({ groups: { '8': 'COMMITTEE:itcom-chair', '42': 'HU:country-president' } }), [
      'COMMITTEE:itcom-chair',
      'HU:country-president'
    ]);
  });
  it('ignores missing, empty and non-string roles, and removes duplicates', () => {
    assert.deepEqual(getRoles({}), []);
    assert.deepEqual(getRoles({ groups: null }), []);
    assert.deepEqual(getRoles({ groups: ['HU:all', '', 7, null, 'HU:all'] as any }), ['HU:all']);
  });
});

describe('section', () => {
  it('is the first section of the section roles, with its label', () => {
    const user = mapUserInfoToUser({
      ...REAL_SHAPED_USERINFO,
      groups: ['CEP:member', 'hu-bupe-obu:section-regular_board_member', 'RO-TIMI-ESN:section-active_member']
    });
    assert.equal(user.sectionCode, 'HU-BUPE-OBU');
    assert.equal(user.section, 'ESN Óbuda University');
  });
  it('falls back to the (deprecated) detailed groups when there are no section roles (spec test 9)', () => {
    const user = mapUserInfoToUser({ ...REAL_SHAPED_USERINFO, groups: undefined });
    assert.equal(user.sectionCode, 'RO-TIMI-ESN');
    assert.equal(user.section, 'ESN Timisoara');
    assert.deepEqual(user.roles, []);
  });
  it('is empty for users without a section (e.g. international roles only)', () => {
    const user = mapUserInfoToUser({ preferred_username: 'x', groups: ['INT:international-staff'] });
    assert.equal(user.sectionCode, null);
    assert.equal(user.section, null);
  });
});

describe('missing optional claims (spec test 11)', () => {
  it("doesn't crash and always has a first name", () => {
    assert.deepEqual(mapUserInfoToUser({ preferred_username: 'jdoe' }), {
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
  });
  it('splits the full name when given and family names are missing', () => {
    const user = mapUserInfoToUser({ preferred_username: 'jdoe', name: 'Jane  Mary Doe' });
    assert.equal(user.firstName, 'Jane');
    assert.equal(user.lastName, 'Mary Doe');
  });
  it('uses the nickname when there is no name at all', () => {
    assert.equal(mapUserInfoToUser({ preferred_username: 'jdoe', nickname: 'Janie' }).firstName, 'Janie');
  });
  it('tolerates malformed detailed groups', () => {
    const user = mapUserInfoToUser({ preferred_username: 'jdoe', detailed_groups: [null, 'x'] as any });
    assert.equal(user.sectionCode, null);
  });
});
