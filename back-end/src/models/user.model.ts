import { Resource } from 'idea-toolbox';

import { UsersOriginDisplayOptions } from './configurations.model';

/**
 * The list of interesting roles on which to assign permissions in the platform.
 */
export enum UserRoles {
  INTERNATIONAL_BOARD = 'INTERNATIONAL_BOARD',
  INTERNATIONAL_SECRETARIAT = 'INTERNATIONAL_SECRETARIAT',
  INTERNATIONAL_LEVEL = 'INTERNATIONAL_LEVEL',
  INTERNATIONAL_GA_CT = 'INTERNATIONAL_GA_CT',
  INTERNATIONAL_AB = 'INTERNATIONAL_AB',
  INTERNATIONAL_AC = 'INTERNATIONAL_AC',
  NATIONAL_BOARD = 'NATIONAL_BOARD',
  NATIONAL_LEVEL = 'NATIONAL_LEVEL',
  LOCAL_BOARD = 'LOCAL_BOARD',
  LOCAL_LEVEL = 'LOCAL_LEVEL'
}

/**
 * The map between the platform's roles with the (known) interesting roles on ESN Accounts, in both the formats of
 * the CAS login (e.g. `local.regularboardmember`) and the OAuth login (`<scope>:<role>`, e.g.
 * `hu-buda-elte:section-regular_board_member`), as in the "ESN Accounts - roles mapping" sheet.
 * "*" stands for any text (e.g. `*:section-*`: any section role of any section).
 * Note: all roles are lower-cased (since they will be handled with a case-insensitive logic).
 */
export const ESN_ACCOUNTS_ROLES_MAP: { [userRole: string]: string[] } = {
  INTERNATIONAL_BOARD: [
    'international.president',
    'international.vicepresident',
    'international.vpgovernance',
    'international.vpdevelopment',
    'international.treasurer',
    'international.webprojectadministrator',
    'international.externalrelations',
    'int:international-board',
    'int:international-president',
    'int:international-vp_governance',
    'int:international-vp_development',
    'int:international-treasurer',
    'int:international-communication',
    'int:international-wpa'
  ],
  INTERNATIONAL_SECRETARIAT: ['international.officestaff', 'int:international-staff'],
  INTERNATIONAL_GA_CT: [
    'international.cnrsecretary',
    'international.agmchair',
    'international.cnradmin',
    'body:ga-chair',
    'body:ga-administrator',
    'body:ga-secretary'
  ],
  INTERNATIONAL_AB: ['international.ab.*', 'body:ab*'],
  INTERNATIONAL_AC: ['international.ac.*', 'body:ac*'],
  // note: the sheet spells the committees' scope both as `COMMITTEE` and `COMMITEE`
  INTERNATIONAL_LEVEL: ['international.*', 'int:*', 'body:*', 'committee:*', 'commitee:*', 'team:*'],
  NATIONAL_BOARD: ['national.regularboardmember', '*:country-regular_board_member'],
  NATIONAL_LEVEL: ['national.*', '*:country-*'],
  LOCAL_BOARD: ['local.regularboardmember', '*:section-regular_board_member'],
  LOCAL_LEVEL: ['local.*', '*:section-*']
};
const escapeRegExp = (text: string): string => text.replace(/[.+?^${}()|[\]\\]/g, '\\$&');

export class User extends Resource {
  /**
   * Username in ESN Accounts (lowercase).
   */
  userId: string;
  /**
   * Email address.
   */
  email: string;
  /**
   * First name.
   */
  firstName: string;
  /**
   * Last name.
   */
  lastName: string;
  /**
   * Section code in ESN Accounts.
   */
  roles: string[];
  /**
   * Section code in ESN Accounts.
   */
  sectionCode: string;
  /**
   * ESN Section.
   */
  section: string;
  /**
   * ESN Country.
   */
  country: string;
  /**
   * The URL to the user's avatar.
   */
  avatarURL: string;
  /**
   * Whether the user is administrator, based on the platform's configurations.
   * A change in this permission will require a new sign-in to take full place.
   */
  isAdministrator: boolean;
  /**
   * Whether the user can manage opportunities, based on the platform's configurations.
   * A change in this permission will require a new sign-in to take full place.
   */
  canManageOpportunities: boolean;
  /**
   * Whether the user can manage the dashboard, based on the platform's configurations.
   * A change in this permission will require a new sign-in to take full place.
   */
  canManageDashboard: boolean;

  /**
   * Whether the user has one of the allowed roles.
   */
  static isAllowedBasedOnRoles = (user: User, allowedRoles: UserRoles[]): boolean => {
    const allowedESNAccountsRoles: string[] = [];
    for (const role of allowedRoles) allowedESNAccountsRoles.push(...ESN_ACCOUNTS_ROLES_MAP[role]);

    return user.roles
      .map(userRole => userRole.toLowerCase())
      .some(userRole =>
        allowedESNAccountsRoles.some(allowedRole =>
          new RegExp(`^${allowedRole.split('*').map(escapeRegExp).join('.*')}$`).test(userRole)
        )
      );
  };

  load(x: any): void {
    super.load(x);
    this.userId = this.clean(x.userId, String)?.toLowerCase();
    this.email = this.clean(x.email, String);
    this.firstName = this.clean(x.firstName, String);
    this.lastName = this.clean(x.lastName, String);
    this.roles = this.cleanArray(x.roles, String);
    this.sectionCode = this.clean(x.sectionCode, String);
    this.section = this.clean(x.section, String);
    this.country = this.clean(x.country, String);
    this.avatarURL = this.clean(x.avatarURL, String);
    this.isAdministrator = this.clean(x.isAdministrator, Boolean);
    this.canManageOpportunities = this.clean(x.canManageOpportunities, Boolean);
    this.canManageDashboard = this.clean(x.canManageDashboard, Boolean);
  }

  /**
   * Get a string representing the origin of the user.
   */
  getOrigin(displayOption: UsersOriginDisplayOptions = UsersOriginDisplayOptions.BOTH): string {
    return getUserOrigin(this, displayOption);
  }
}

/**
 * Get a string representing the origin of a user.
 */
export const getUserOrigin = (
  user: { country?: string; section?: string },
  displayOption: UsersOriginDisplayOptions
): string => {
  if (displayOption === UsersOriginDisplayOptions.COUNTRY) return user.country;
  if (displayOption === UsersOriginDisplayOptions.SECTION) return user.section;
  if (displayOption === UsersOriginDisplayOptions.BOTH) {
    if (user.country === user.section) return user.section;
    return [user.country, user.section].filter(x => x).join(' - ');
  } else return null;
};
