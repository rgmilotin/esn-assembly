/**
 * Map the userinfo of ESN Accounts (OAuth 2.0) to the platform's user, in the same shape produced by the CAS login.
 *
 * The rules were checked against a real userinfo (an active member of two sections) and the user that the CAS login
 * produced for the same person. What a real profile hasn't shown yet (e.g. national or international roles) is marked
 * with "ASSUMPTION"; the `esnaccOAuth` handler logs (at DEBUG level, i.e. on dev) the claims received and the values
 * mapped, so they can be verified.
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
  // the CAS login uses the (lower-cased) CAS username as user ID: it's the value of `legacy_sub`
  const legacyId = userInfo.legacy_sub ?? userInfo.sub_legacy;
  const userId = cleanString(legacyId)?.toLowerCase();
  if (!userId)
    throw new MissingLegacyIdError(
      `The ESN Accounts profile has no \`legacy_sub\` text (found: ${describeValue(legacyId)}).`
    );

  const { firstName, lastName } = getNames(userInfo, userId);
  const { sectionCode, section, country } = getSectionAndCountry(userInfo);

  return {
    userId,
    // the email of the CAS login is the one in `esn_email` (`email` can be a different, personal one)
    email: cleanString(userInfo.esn_email) ?? cleanString(userInfo.email),
    firstName,
    lastName,
    roles: toLegacyRoles(roles),
    sectionCode,
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

const SECTION_GROUP_TYPES = ['section'];
/**
 * ASSUMPTION: the type of the `detailed_groups` of a national organisation (a real profile hasn't shown one yet).
 */
const COUNTRY_GROUP_TYPES = ['country', 'national', 'national_organisation', 'national_organization'];

const getSectionAndCountry = (userInfo: UserInfo): { sectionCode: string; section: string; country: string } => {
  const detailedGroups = Array.isArray(userInfo.detailed_groups) ? userInfo.detailed_groups : [];
  const groupType = (group: { type?: string }): string => cleanString(group?.type)?.toLowerCase();

  // the first section is the main one, like the single section returned by CAS; its `scope` is the section code
  const sectionGroup = detailedGroups.find(group => SECTION_GROUP_TYPES.includes(groupType(group)));
  const countryGroup = detailedGroups.find(group => COUNTRY_GROUP_TYPES.includes(groupType(group)));

  const sectionCode = cleanString(sectionGroup?.scope);
  // CAS returned the name of the ESN country (e.g. "ESN Romania"), which the userinfo lacks: when there's no group
  // of the country, it's built from the country code that starts the section code (e.g. "RO-TIMI-ESN");
  // note: `address.country` is the user's personal address, not the ESN country, so it's never used
  return {
    sectionCode,
    section: cleanString(sectionGroup?.label),
    country: cleanString(countryGroup?.label) ?? getESNCountryName(sectionCode)
  };
};

/**
 * ASSUMPTION: the ESN country's name is "ESN " + the country's English name, as for "ESN Romania" or "ESN Hungary";
 * a few countries may be named differently by ESN (e.g. "Czechia" / "Czech Republic").
 */
const getESNCountryName = (sectionCode: string | null): string | null => {
  const countryCode = sectionCode?.match(/^([A-Z]{2})-/)?.[1];
  if (!countryCode) return null;
  try {
    const countryName = new Intl.DisplayNames(['en'], { type: 'region' }).of(countryCode);
    return countryName && countryName !== countryCode ? `ESN ${countryName}` : null;
  } catch {
    return null;
  }
};

//
// ROLES
//

type LegacyLevel = 'Local' | 'National' | 'International';

/**
 * The type of an ESN Accounts' role (the part before the first "-", e.g. `section` in `section-active_member`)
 * and the level of the corresponding legacy (CAS) role; checked on a real profile for `section`.
 * ASSUMPTION: `country` and `international` (a real profile hasn't shown them yet).
 */
const ROLE_TYPE_LEVELS: Record<string, LegacyLevel> = {
  section: 'Local',
  country: 'National',
  international: 'International'
};
/**
 * ASSUMPTION (the spec's example, e.g. `NATIONAL_ORGANISATION:president`): group types used as a role's prefix,
 * and the corresponding level of the legacy (CAS) roles.
 */
const GROUP_TYPE_LEVELS: Record<string, LegacyLevel> = {
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
 * The format of ESN Accounts' roles: `<type>-<name>`, e.g. `section-active_member`.
 */
const TYPED_ROLE_REGEX = /^([A-Za-z]+)-([A-Za-z0-9_\- ]+)$/;
/**
 * ASSUMPTION (the spec's example): a role with its group type as prefix, e.g. `NATIONAL_ORGANISATION:president`.
 */
const PREFIXED_ROLE_REGEX = /^([A-Za-z_]+):([A-Za-z0-9_\- ]+)$/;

/**
 * Translate the roles of ESN Accounts into the legacy (CAS) format used by the platform's role rules
 * (`ESN_ACCOUNTS_ROLES_MAP` in `user.model.ts`), e.g. `section-active_member` → `Local.activeMember`.
 * Roles with no legacy equivalent (e.g. the generic `all` of a section, or the `member` of a regional platform)
 * are skipped, as CAS didn't return them either.
 */
export function toLegacyRoles(entries: RoleEntry[]): string[] {
  const legacyRoles = entries.map(entry => toLegacyRole(entry)).filter(role => !!role);
  return legacyRoles.filter((role, index) => legacyRoles.indexOf(role) === index);
}

export function toLegacyRole(entry: RoleEntry): string | null {
  const role = cleanString(entry?.role);
  if (!role) return null;

  const legacy = role.match(LEGACY_ROLE_REGEX);
  if (legacy) return `${GROUP_TYPE_LEVELS[legacy[1].toLowerCase()]}.${legacy[2]}`;

  const typed = role.match(TYPED_ROLE_REGEX);
  const typedLevel = typed ? ROLE_TYPE_LEVELS[typed[1].toLowerCase()] : undefined;
  if (typedLevel) return toLegacyRoleName(typedLevel, typed[2]);

  const prefixed = role.match(PREFIXED_ROLE_REGEX);
  if (!prefixed) return null;
  // `detailed_groups` describe the group: their scope/type are more reliable than the role's prefix
  const prefixedLevel = [entry.scope, entry.type, prefixed[1]]
    .map(hint => cleanString(hint)?.toLowerCase())
    .map(hint => (hint ? GROUP_TYPE_LEVELS[hint] : undefined))
    .find(found => !!found);
  return prefixedLevel ? toLegacyRoleName(prefixedLevel, prefixed[2]) : null;
}

const toLegacyRoleName = (level: LegacyLevel, roleName: string): string | null => {
  const name = toCamelCase(roleName);
  return name ? `${level}.${name}` : null;
};

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

/**
 * The type of a value, for logs (never the value itself).
 */
const describeValue = (value: unknown): string => {
  if (value === undefined) return 'missing';
  if (value === null) return 'null';
  if (typeof value === 'string') return value.trim() ? 'text' : 'empty text';
  return Array.isArray(value) ? 'array' : typeof value;
};
