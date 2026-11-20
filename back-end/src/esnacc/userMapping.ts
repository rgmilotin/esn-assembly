/**
 * Map the userinfo of ESN Accounts (OAuth 2.0) to the platform's user, in the same shape produced by the CAS login.
 */

import { ESNDetailedGroup, UserInfo } from './types';

/**
 * The account has no valid username: the sign-in is refused, since the username is the platform's user ID.
 */
export class MissingUsernameError extends Error {}

/**
 * The maximum length of an ESN Accounts (Drupal) username.
 */
const USERNAME_MAX_LENGTH = 60;

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

export const mapUserInfoToUser = (userInfo: UserInfo): MappedUserData => {
  const userId = getUserId(userInfo);
  const { firstName, lastName } = getNames(userInfo, userId);
  const roles = getRoles(userInfo);
  const sectionCode = getMainSectionCode(userInfo, roles);

  return {
    userId,
    // the email of the CAS login is the one in `esn_email` (`email` can be a different, personal one)
    email: cleanString(userInfo.esn_email) ?? cleanString(userInfo.email),
    firstName,
    lastName,
    // roles in the OAuth format (`<scope>:<role>`), recognised by `ESN_ACCOUNTS_ROLES_MAP` (`user.model.ts`)
    roles,
    sectionCode,
    section: cleanString(getDetailedGroups(userInfo).find(group => group.scope === sectionCode)?.label),
    country: null,
    avatarURL: cleanString(userInfo.picture)
  };
};

/**
 * The user ID is the ESN Accounts username (`preferred_username`), normalised exactly as the CAS login normalises the
 * CAS username (lower-cased), so that the same person gets the same account with both sign-in methods.
 * The username is required and must be a valid ESN Accounts username (no control characters, max 60 characters).
 * Note: `sub` (a UUID) and `legacy_sub`/`sub_legacy` are intentionally not used.
 */
export const getUserId = (userInfo: UserInfo): string => {
  const username = userInfo?.preferred_username;
  if (typeof username !== 'string' || !username.trim())
    throw new MissingUsernameError('The ESN Accounts profile has no `preferred_username`');

  const userId = username.trim().toLowerCase();
  // eslint-disable-next-line no-control-regex
  if (userId.length > USERNAME_MAX_LENGTH || /[\u0000-\u001f\u007f]/.test(userId))
    throw new MissingUsernameError('The `preferred_username` of the ESN Accounts profile is not a valid username');

  return userId;
};

/**
 * The OAuth roles (`groups`), as `<scope>:<role>` strings; ESN Accounts may return an array or an object
 * (`{ "<groupId>": "<role>" }`, as in the spec). Duplicates are removed, keeping the order.
 */
export const getRoles = (userInfo: UserInfo): string[] => {
  const groups = userInfo?.groups;
  const values: unknown[] = Array.isArray(groups)
    ? groups
    : groups && typeof groups === 'object'
      ? Object.values(groups)
      : [];
  const roles = values.filter((role): role is string => typeof role === 'string' && !!role.trim()).map(r => r.trim());
  return Array.from(new Set(roles));
};

/**
 * The main section of the user, i.e. the first one returned (like the single section returned by the CAS login):
 * from the section roles (`<SECTION-CODE>:section-<role>`) or, if none, from the (deprecated) `detailed_groups`.
 */
const getMainSectionCode = (userInfo: UserInfo, roles: string[]): string => {
  const fromRoles = roles.map(role => role.match(SECTION_ROLE)?.[1]).find(code => code);
  if (fromRoles) return fromRoles.toUpperCase();
  const fromDetailedGroups = getDetailedGroups(userInfo).find(group => group.type === 'section');
  return cleanString(fromDetailedGroups?.scope)?.toUpperCase() ?? null;
};
const SECTION_ROLE = /^([A-Za-z]{2}-[A-Za-z0-9]+-[A-Za-z0-9]+):section-/;

const getDetailedGroups = (userInfo: UserInfo): ESNDetailedGroup[] =>
  (Array.isArray(userInfo?.detailed_groups) ? userInfo.detailed_groups : []).filter(
    group => group && typeof group === 'object'
  );

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

const cleanString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
};
