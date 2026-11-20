/**
 * The directory of ESN Accounts' sections and countries (public endpoints `/api/v2/sections` and `/api/v2/countries`),
 * used to resolve the user's section and country names from their codes, instead of guessing them from strings.
 *
 * Strategy: the directory is loaded at sign-in time and cached in the Lambda's memory (shared by the following
 * sign-ins while the Lambda is warm) for `DIRECTORY_CACHE_TTL_MS`; the two lists change rarely and are small enough
 * (~700 KB and ~30 KB). If ESN Accounts is unavailable, the last loaded directory is used (even if older); if there's
 * none, the sign-in continues anyway, with the section's name from the userinfo and no country. After a failure, the
 * load is retried only after `DIRECTORY_RETRY_AFTER_MS`, so that an outage doesn't slow down every sign-in.
 */

import { HttpClient, axiosHttpClient } from './esnaccount';
import { MappedUserData } from './userMapping';

/**
 * How long the loaded directory is considered fresh.
 */
export const DIRECTORY_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
/**
 * How long to wait for ESN Accounts' directory before going on without it (the sign-in must not be blocked).
 */
export const DIRECTORY_REQUEST_TIMEOUT_MS = 3000;
/**
 * After a failed load, how long to wait before trying again (meanwhile, sign-ins don't wait for ESN Accounts).
 */
export const DIRECTORY_RETRY_AFTER_MS = 5 * 60 * 1000;

export interface ESNDirectory {
  /**
   * Sections by (upper-cased) code, e.g. `HU-BUPE-ELT` → `{ label: 'ESN ELTE', countryCode: 'HU' }`.
   */
  sections: Map<string, { label: string; countryCode: string }>;
  /**
   * Countries' labels by (upper-cased) code, e.g. `HU` → `ESN Hungary`.
   */
  countries: Map<string, string>;
}

/**
 * Create a loader of the directory with its own in-memory cache; `load()` never throws: it returns `null` when no
 * directory could ever be loaded.
 */
export const createDirectoryLoader = (params: {
  sectionsEndpoint: string;
  countriesEndpoint: string;
  http?: HttpClient;
  ttlMs?: number;
  now?: () => number;
  onError?: (error: Error) => void;
}): { load: () => Promise<ESNDirectory | null> } => {
  const http = params.http ?? axiosHttpClient;
  const ttlMs = params.ttlMs ?? DIRECTORY_CACHE_TTL_MS;
  const now = params.now ?? Date.now;

  let cached: { directory: ESNDirectory; loadedAt: number } | null = null;
  let loading: Promise<ESNDirectory | null> | null = null;
  let retryAfter = 0;

  const fetchDirectory = async (): Promise<ESNDirectory | null> => {
    try {
      const [sections, countries] = await Promise.all([
        fetchList(http, params.sectionsEndpoint),
        fetchList(http, params.countriesEndpoint)
      ]);
      const directory = parseDirectory(sections, countries);
      cached = { directory, loadedAt: now() };
      return directory;
    } catch (error) {
      retryAfter = now() + DIRECTORY_RETRY_AFTER_MS;
      params.onError?.(error as Error);
      return cached?.directory ?? null;
    } finally {
      loading = null;
    }
  };

  return {
    load: async (): Promise<ESNDirectory | null> => {
      if (cached && now() - cached.loadedAt < ttlMs) return cached.directory;
      if (now() < retryAfter) return cached?.directory ?? null;
      if (!loading) loading = fetchDirectory();
      return loading;
    }
  };
};

const fetchList = async (http: HttpClient, url: string): Promise<unknown[]> => {
  const response = await http.request({
    method: 'GET',
    url,
    headers: { Accept: 'application/json' },
    timeoutMs: DIRECTORY_REQUEST_TIMEOUT_MS
  });
  if (response.status < 200 || response.status >= 300) throw new Error(`${url} returned HTTP ${response.status}`);
  let list: unknown;
  try {
    list = JSON.parse(response.body);
  } catch {
    throw new Error(`${url} returned invalid JSON`);
  }
  if (!Array.isArray(list)) throw new Error(`${url} didn't return a list`);
  return list;
};

/**
 * Build the directory from the lists of ESN Accounts, skipping the malformed entries.
 */
export const parseDirectory = (sectionsList: unknown[], countriesList: unknown[]): ESNDirectory => {
  const sections = new Map<string, { label: string; countryCode: string }>();
  for (const item of sectionsList as any[]) {
    const code = cleanCode(item?.code);
    const label = cleanString(item?.label);
    if (code && label) sections.set(code, { label, countryCode: cleanCode(item?.cc) ?? code.slice(0, 2) });
  }

  const countries = new Map<string, string>();
  for (const item of countriesList as any[]) {
    const code = cleanCode(item?.code ?? item?.cc);
    const label = cleanString(item?.label);
    if (code && label) countries.set(code, label);
  }

  if (!sections.size || !countries.size) throw new Error('The directory of ESN Accounts is empty');
  return { sections, countries };
};

/**
 * Complete the user's section and country (as the CAS login returned them, e.g. "ESN ELTE" and "ESN Hungary")
 * from the directory:
 *  - the section's name is the directory's label of the section code (else, the one from the userinfo);
 *  - the country is the directory's label of the section's country or, for users without a section, of the first
 *    country in their roles (`<COUNTRY-CODE>:country-<role>`, then `<COUNTRY-CODE>:all`).
 */
export const resolveSectionAndCountry = (user: MappedUserData, directory: ESNDirectory | null): MappedUserData => {
  if (!directory) return { ...user };

  const section = user.sectionCode ? directory.sections.get(user.sectionCode.toUpperCase()) : undefined;
  const countryCode = section?.countryCode ?? getCountryCodeFromRoles(user.roles);
  const country = countryCode ? directory.countries.get(countryCode) : undefined;

  return { ...user, section: section?.label ?? user.section, country: country ?? user.country };
};

const getCountryCodeFromRoles = (roles: string[]): string | null => {
  const countryOf = (pattern: RegExp): string | undefined =>
    roles.map(role => role.match(pattern)?.[1]).find(code => code);
  return (countryOf(/^([A-Za-z]{2}):country-/) ?? countryOf(/^([A-Za-z]{2}):all$/))?.toUpperCase() ?? null;
};

const cleanString = (value: unknown): string | null => {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
};
const cleanCode = (value: unknown): string | null => cleanString(value)?.toUpperCase() ?? null;
