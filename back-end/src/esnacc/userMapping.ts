/**
 * Map the userinfo of ESN Accounts (OAuth 2.0) to the platform's user, in the same shape produced by the CAS login.
 * Checked against a real userinfo and the user that the CAS login produced for the same person.
 */

import { UserInfo } from './types';

/**
 * The account has no username: the sign-in is refused, since the username is the platform's user ID.
 */
export class MissingUsernameError extends Error {}

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

export function mapUserInfoToUser(userInfo: UserInfo): MappedUserData {
  // the user ID is the (lower-cased) ESN Accounts username, as for the CAS login
  const userId = cleanString(userInfo.preferred_username)?.toLowerCase();
  if (!userId) throw new MissingUsernameError('The ESN Accounts profile has no `preferred_username`.');

  const { firstName, lastName } = getNames(userInfo, userId);
  // the first section is the main one, like the single section returned by CAS; its `scope` is the section code
  const groups = Array.isArray(userInfo.detailed_groups) ? userInfo.detailed_groups : [];
  const section = groups.find(group => group?.type === 'section');
  const sectionCode = cleanString(section?.scope);

  return {
    userId,
    // the email of the CAS login is the one in `esn_email` (`email` can be a different, personal one)
    email: cleanString(userInfo.esn_email) ?? cleanString(userInfo.email),
    firstName,
    lastName,
    // roles in the OAuth format (`<scope>:<role>`), recognised by `ESN_ACCOUNTS_ROLES_MAP` (`user.model.ts`)
    roles: (Array.isArray(userInfo.groups) ? userInfo.groups : []).filter(role => typeof role === 'string'),
    sectionCode,
    section: cleanString(section?.label),
    country: getESNCountryName(sectionCode),
    avatarURL: cleanString(userInfo.picture)
  };
}

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

/**
 * CAS returned the name of the ESN country, which the userinfo doesn't have: it's built from the country code that
 * starts the section code (e.g. `RO-TIMI-ESN` → "ESN Romania").
 */
const getESNCountryName = (sectionCode: string | null): string | null => {
  const countryCode = sectionCode?.match(/^([A-Z]{2})-/)?.[1];
  if (!countryCode) return null;
  const countryName = new Intl.DisplayNames(['en'], { type: 'region' }).of(countryCode);
  return countryName && countryName !== countryCode ? `ESN ${countryName}` : null;
};

const cleanString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
};
