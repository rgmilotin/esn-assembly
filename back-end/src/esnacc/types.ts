/**
 * ESN Accounts entities, as described by `ESNacc_OAUTH_INTEGRATION_SPEC.md` (ESN-Hungary/esnscope).
 * All the fields are optional, unless ESN Accounts explicitly guarantees them.
 */

export interface TokenResponse {
  access_token?: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  [key: string]: unknown;
}

export interface ESNUserAddress {
  street_address?: string;
  address_line1?: string;
  address_line2?: string;
  locality?: string;
  postal_code?: string;
  cc?: string;
  country?: string;
}

export interface ESNSocialMedia {
  sm_ln?: string;
  sm_ig?: string;
  sm_tw?: string;
  sm_fb?: string;
}

/**
 * Deprecated (CAS) representation of a role.
 */
export interface ESNDetailedRole {
  role: string;
  label: string;
}

/**
 * Deprecated (CAS) representation of a group; ESN Accounts may return one role object or an array.
 */
export interface ESNDetailedGroup {
  label: string;
  type: string;
  scope: string;
  roles: ESNDetailedRole[] | ESNDetailedRole;
}

export interface UserInfo {
  sub?: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  esn_email?: string;
  nickname?: string;
  /**
   * The ESN Accounts username: it's the ID of the users in the platform.
   */
  preferred_username?: string;
  gender?: string;
  birthdate?: string;
  address?: ESNUserAddress;
  other?: ESNSocialMedia;
  updated_at?: number;
  nationality?: string;
  /**
   * Groups (sections, regional platforms, etc.) and the user's roles in them; `scope` is e.g. the section code.
   */
  detailed_groups?: ESNDetailedGroup[];
  /**
   * OAuth 2.0 roles, as `<scope>:<role>`: e.g. `HU-BUDA-ELTE:section-active_member`, `HU:country-president`.
   */
  groups?: string[];
  [key: string]: unknown;
}

/**
 * The data kept (signed) in a cookie between the authorization request and the callback.
 */
export interface OAuthRequestCookie {
  state: string;
  codeVerifier: string;
  /**
   * When the flow started from a local development front-end, its port (e.g. 8100).
   */
  localhostPort?: number;
}
