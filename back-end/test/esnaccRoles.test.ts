/**
 * Tests of the mapping of the ESN Accounts roles (CAS and OAuth 2.0) to the platform's roles, with the cases of the
 * official "ESN Accounts - roles mapping" sheet. Run with: `npm test`.
 */

import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

import { User, UserRoles, matchesESNAccountsRole } from '../src/models/user.model';

const ALL_ROLES = Object.values(UserRoles);

/**
 * The platform's roles of a user with the given ESN Accounts roles.
 */
const platformRolesOf = (...roles: string[]): UserRoles[] =>
  ALL_ROLES.filter(role => User.isAllowedBasedOnRoles(new User({ userId: 'x', roles }), [role])).sort();

const sorted = (...roles: UserRoles[]): UserRoles[] => [...roles].sort();

const { INTERNATIONAL_LEVEL, NATIONAL_LEVEL, LOCAL_LEVEL } = UserRoles;

describe('OAuth roles of the sheet: local level', () => {
  it('a section board member is local board', () => {
    assert.deepEqual(
      platformRolesOf('HU-BUPE-ELT:section-regular_board_member'),
      sorted(UserRoles.LOCAL_BOARD, LOCAL_LEVEL)
    );
  });
  it('the other section roles are local level only', () => {
    const sectionRoles = [
      'president',
      'vice_president',
      'treasurer',
      'communication',
      'secretary',
      'board_support',
      'webmaster',
      'project_coordinator',
      'activity_coordinator',
      'event_coordinator',
      'esncard',
      'active_member',
      'alumnus'
    ];
    for (const role of sectionRoles)
      assert.deepEqual(platformRolesOf(`RO-TIMI-ESN:section-${role}`), [LOCAL_LEVEL], role);
  });
});

describe('OAuth roles of the sheet: national level', () => {
  it('a country board member is national board', () => {
    assert.deepEqual(
      platformRolesOf('HU:country-regular_board_member'),
      sorted(UserRoles.NATIONAL_BOARD, NATIONAL_LEVEL)
    );
  });
  it('the other country roles are national level only', () => {
    const countryRoles = [
      'president',
      'vice_president',
      'treasurer',
      'communication',
      'secretary',
      'staff',
      'board_support',
      'webmaster',
      'project_coordinator',
      'auditor',
      'education',
      'activity_coordinator',
      'event_coordinator',
      'esncard',
      'alumnus'
    ];
    for (const role of countryRoles) assert.deepEqual(platformRolesOf(`HU:country-${role}`), [NATIONAL_LEVEL], role);
  });
});

describe('OAuth roles of the sheet: international level', () => {
  it('the international board', () => {
    const boardRoles = ['board', 'president', 'vp_governance', 'vp_development', 'treasurer', 'communication', 'wpa'];
    for (const role of boardRoles)
      assert.deepEqual(
        platformRolesOf(`INT:international-${role}`),
        sorted(UserRoles.INTERNATIONAL_BOARD, INTERNATIONAL_LEVEL),
        role
      );
  });
  it('the international secretariat (staff)', () => {
    assert.deepEqual(
      platformRolesOf('INT:international-staff'),
      sorted(UserRoles.INTERNATIONAL_SECRETARIAT, INTERNATIONAL_LEVEL)
    );
  });
  it('other international roles are international level only', () => {
    for (const role of ['liaison_officer', 'hr_manager', 'accountant', 'administrator', 'board_alumnus'])
      assert.deepEqual(platformRolesOf(`INT:international-${role}`), [INTERNATIONAL_LEVEL], role);
  });
  it('the General Assembly chairing team', () => {
    for (const role of ['BODY:ga-chair', 'BODY:ga-administrator', 'BODY:ga-secretary'])
      assert.deepEqual(platformRolesOf(role), sorted(UserRoles.INTERNATIONAL_GA_CT, INTERNATIONAL_LEVEL), role);
    assert.deepEqual(platformRolesOf('BODY:ga'), [INTERNATIONAL_LEVEL]);
  });
  it('the Arbitration Board and the Audit Commission', () => {
    for (const role of ['BODY:ab', 'BODY:ab-main_arbitrator', 'BODY:ab-legal_expert', 'BODY:ab-secretary'])
      assert.deepEqual(platformRolesOf(role), sorted(UserRoles.INTERNATIONAL_AB, INTERNATIONAL_LEVEL), role);
    for (const role of ['BODY:ac', 'BODY:ac-main_auditor', 'BODY:ac-financial_auditor', 'BODY:ac-audit_team_member'])
      assert.deepEqual(platformRolesOf(role), sorted(UserRoles.INTERNATIONAL_AC, INTERNATIONAL_LEVEL), role);
  });
  it('committees (in both the spellings of the sheet) and teams are international level', () => {
    const roles = [
      'COMMITTEE:itcom',
      'COMMITTEE:itcom-chair',
      'COMMITEE:nec-vice_chair',
      'TEAM:esncard-coordinator',
      'TEAM:cm-it',
      'TEAM:eduk8-facilitator',
      'TEAM:egm-ct_member',
      'TEAM:rst-rcc'
    ];
    for (const role of roles) assert.deepEqual(platformRolesOf(role), [INTERNATIONAL_LEVEL], role);
  });
});

describe('OAuth roles that grant nothing', () => {
  it('generic memberships, regional platforms and tool permissions', () => {
    for (const role of ['HU:all', 'HU-BUPE-ELT:all', 'CEP:member', 'SEEP:member', 'PERMISSIONS:it-wiki_admin'])
      assert.deepEqual(platformRolesOf(role), [], role);
    assert.deepEqual(platformRolesOf(), []);
  });
  it('look-alike roles', () => {
    for (const role of ['BODY:abc', 'BODY:ac_x', 'HU:country', 'x:section', 'internationalXab.y', 'int'])
      assert.ok(!platformRolesOf(role).some(r => r !== INTERNATIONAL_LEVEL), role);
    assert.deepEqual(platformRolesOf('HU:country'), []);
    assert.deepEqual(platformRolesOf('internationalXab.y'), []);
  });
});

describe('roles in general', () => {
  it('a real-shaped OAuth profile (active member of two sections) is local level only', () => {
    const roles = ['RO-TIMI-ESN:section-active_member', 'RO:all', 'HU-BUPE-OBU:section-active_member', 'CEP:member'];
    assert.deepEqual(platformRolesOf(...roles), [LOCAL_LEVEL]);
  });
  it('are case-insensitive', () => {
    assert.deepEqual(
      platformRolesOf('hu:COUNTRY-Regular_Board_Member'),
      sorted(UserRoles.NATIONAL_BOARD, NATIONAL_LEVEL)
    );
  });
  it('still recognise the CAS roles as before', () => {
    assert.deepEqual(platformRolesOf('Local.regularBoardMember'), sorted(UserRoles.LOCAL_BOARD, LOCAL_LEVEL));
    assert.deepEqual(platformRolesOf('Local.activeMember'), [LOCAL_LEVEL]);
    assert.deepEqual(platformRolesOf('National.regularBoardMember'), sorted(UserRoles.NATIONAL_BOARD, NATIONAL_LEVEL));
    assert.deepEqual(
      platformRolesOf('International.president'),
      sorted(UserRoles.INTERNATIONAL_BOARD, INTERNATIONAL_LEVEL)
    );
    assert.deepEqual(
      platformRolesOf('International.AB.MainArbitrator'),
      sorted(UserRoles.INTERNATIONAL_AB, INTERNATIONAL_LEVEL)
    );
    assert.deepEqual(
      platformRolesOf('International.agmchair'),
      sorted(UserRoles.INTERNATIONAL_GA_CT, INTERNATIONAL_LEVEL)
    );
  });
  it('matches "*" anywhere and treats the other characters literally', () => {
    assert.ok(matchesESNAccountsRole('hu:country-x', '*:country-*'));
    assert.ok(matchesESNAccountsRole('international.ab.x', 'international.ab.*'));
    assert.ok(!matchesESNAccountsRole('internationalxab.x', 'international.ab.*'));
    assert.ok(!matchesESNAccountsRole('xlocal.regularboardmember', 'local.regularboardmember'));
    assert.ok(!matchesESNAccountsRole('local.regularboardmemberx', 'local.regularboardmember'));
  });
});
