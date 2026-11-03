/**
 * Map the userinfo of ESN Accounts (OAuth 2.0) to the platform's user, in the same shape produced by the CAS login.
 *
 * BEST EFFORT: the OAuth format of roles, sections and countries hasn't been checked against real userinfo samples
 * yet. Every guess is marked with "ASSUMPTION"; the `esnaccOAuth` handler logs (at DEBUG level, i.e. on dev) the claims
 * received and the values mapped, so they can be verified and these rules fixed.
 */

import { RoleEntry, UserInfo } from './types';

/**
 * The account has no legacy (CAS) username: the sign-in is refused, otherwise the same person would end up being
 * a different user than the one created by the CAS login (and lose admin rights, badges, questions, etc.).
 */
export class MissingLegacyIdError extends Error {}

/**
 * The user's fields that the CAS login reads from ESN Accounts.
 */
export interface MappedUserData {
  userId: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: string[];
  sectionCode: string;
  section: string;
  country: string;
  avatarURL: string;
}

export function mapUserInfoToUser(userInfo: UserInfo, roles: RoleEntry[]): MappedUserData {
  // the CAS login uses the (lower-cased) CAS username as user ID: `sub_legacy` must be the same value
  const userId = cleanString(userInfo.sub_legacy)?.toLowerCase();
  if (!userId) throw new MissingLegacyIdError('The ESN Accounts profile has no `sub_legacy`.');

  const { firstName, lastName } = getNames(userInfo, userId);
  const { section, country } = getSectionAndCountry(userInfo);

  return {
    userId,
    email: cleanString(userInfo.email) ?? cleanString(userInfo.esn_email),
    firstName,
    lastName,
    roles: toLegacyRoles(roles),
    // ASSUMPTION: no claim with the section code is documented; these are the names it would most likely have
    sectionCode: getStringClaim(userInfo, ['sc', 'section_code', 'sectionCode']),
    section,
    country,
    avatarURL: cleanString(userInfo.picture)
  };
}

//
// NAMES
//

const getNames = (userInfo: UserInfo, userId: string): { firstName: string; lastName: string } => {
  let firstName = cleanString(userInfo.given_name);
  let lastName = cleanString(userInfo.family_name);

  if (!firstName && !lastName) {
    const fullName = cleanString(userInfo.name);
    if (fullName) {
      const [first, ...rest] = fullName.split(/\s+/);
      firstName = first;
      lastName = rest.join(' ') || null;
    }
  }

  // the platform builds display names from the first name: it can never be empty
  return { firstName: firstName ?? cleanString(userInfo.nickname) ?? userId, lastName: lastName ?? '' };
};

//
// SECTION AND COUNTRY
//

const SECTION_GROUP_TYPES = ['section', 'local'];
const COUNTRY_GROUP_TYPES = ['country', 'national', 'national_organisation', 'national_organization'];

const getSectionAndCountry = (userInfo: UserInfo): { section: string; country: string } => {
  let section: string = null;
  let country: string = null;

  // ASSUMPTION: the (deprecated CAS) `detailed_groups` include the user's section and country, by `type`;
  // with more than one section, the first one is used (CAS returned a single section)
  const detailedGroups = Array.isArray(userInfo.detailed_groups) ? userInfo.detailed_groups : [];
  for (const group of detailedGroups) {
    const type = cleanString(group?.type)?.toLowerCase();
    if (!section && SECTION_GROUP_TYPES.includes(type)) section = cleanString(group.label);
    if (!country && COUNTRY_GROUP_TYPES.includes(type)) country = cleanString(group.label);
  }

  // ASSUMPTION: top-level `section` and `country` claims, if ESN Accounts adds them (`address.country` is the user's
  // personal address, not the ESN country, so it's never used)
  return {
    section: section ?? getStringClaim(userInfo, ['section']),
    country: country ?? getStringClaim(userInfo, ['country'])
  };
};

//
// ROLES
//

type LegacyLevel = 'Local' | 'National' | 'International';

/**
 * Group types/scopes/prefixes and the corresponding level of the legacy (CAS) roles.
 */
const LEGACY_LEVELS: Record<string, LegacyLevel> = {
  section: 'Local',
  local: 'Local',
  country: 'National',
  national: 'National',
  national_organisation: 'National',
  national_organization: 'National',
  international: 'International',
  committee: 'International'
};

/**
 * A role already in the legacy format, possibly with a scope (CAS extended role): `Local.activeMember:HU-BUPE-OBU`.
 */
const LEGACY_ROLE_REGEX = /^(local|national|international)\.([A-Za-z0-9_.-]+)(?::.*)?$/i;
/**
 * ASSUMPTION: an OAuth role with its group type as prefix, e.g. `NATIONAL_ORGANISATION:president` (spec's example).
 */
const PREFIXED_ROLE_REGEX = /^([A-Za-z_]+):([A-Za-z0-9_\- ]+)$/;
/**
 * ASSUMPTION: a role named after its group type, e.g. `country-president` (ESN Accounts' group roles).
 */
const GROUP_ROLE_REGEX = /^(section|country)-([A-Za-z0-9_\- ]+)$/i;

/**
 * Translate the roles of ESN Accounts into the legacy (CAS) format used by the platform's role rules
 * (`ESN_ACCOUNTS_ROLES_MAP` in `user.model.ts`), e.g. `Local.regularBoardMember`; unknown roles are skipped.
 */
export function toLegacyRoles(entries: RoleEntry[]): string[] {
  const legacyRoles = entries.map(entry => toLegacyRole(entry)).filter(role => !!role);
  return legacyRoles.filter((role, index) => legacyRoles.indexOf(role) === index);
}

export function toLegacyRole(entry: RoleEntry): string | null {
  const role = cleanString(entry?.role);
  if (!role) return null;

  const legacy = role.match(LEGACY_ROLE_REGEX);
  if (legacy) return `${LEGACY_LEVELS[legacy[1].toLowerCase()]}.${legacy[2]}`;

  let levelHint: string;
  let roleName: string;
  const prefixed = role.match(PREFIXED_ROLE_REGEX);
  const groupRole = role.match(GROUP_ROLE_REGEX);
  if (prefixed) [levelHint, roleName] = [prefixed[1], prefixed[2]];
  else if (groupRole) [levelHint, roleName] = [groupRole[1], groupRole[2]];
  else return null;

  // `detailed_groups` describe the group: their scope/type are more reliable than the role's prefix
  const level = [entry.scope, entry.type, levelHint]
    .map(hint => cleanString(hint)?.toLowerCase())
    .map(hint => (hint ? LEGACY_LEVELS[hint] : undefined))
    .find(found => !!found);
  if (!level) return null;

  const name = toCamelCase(roleName);
  return name ? `${level}.${name}` : null;
}

/**
 * E.g. `regular_board_member` or `regular-board-member` → `regularBoardMember`.
 */
const toCamelCase = (value: string): string =>
  value
    .trim()
    .toLowerCase()
    .split(/[-_\s]+/)
    .filter(word => !!word)
    .map((word, index) => (index === 0 ? word : word.charAt(0).toUpperCase().concat(word.slice(1))))
    .join('');

//
// HELPERS
//

const cleanString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
};

const getStringClaim = (userInfo: UserInfo, claims: string[]): string | null =>
  claims.map(claim => cleanString(userInfo[claim])).find(value => !!value) ?? null;
