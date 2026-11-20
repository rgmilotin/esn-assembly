# Sign-in with ESN Accounts through OAuth 2.0

The sign-in page offers:

1. **Sign in with ESN Accounts**: the original CAS login (`back-end/src/handlers/login.ts`), unchanged.
2. **Sign in with ESN Accounts (OAuth)**: OAuth 2.0 authorization code flow with PKCE (S256) and `state`, following
   [`ESNacc_OAUTH_INTEGRATION_SPEC.md`](https://github.com/ESN-Hungary/esnscope/blob/main/ESNacc_OAUTH_INTEGRATION_SPEC.md)
   (reference implementation: [ESNscope](https://github.com/ESN-Hungary/esnscope)).
3. **Sign in with Google**: a placeholder; it only shows the message "Function coming soon!".

The OAuth sign-in is always available, like CAS: there is no switch to turn it off.

## How it works

```text
Browser                                GA app API (Lambda esnaccOAuth)                  ESN Accounts
   |-- GET /<stage>/esnacc_oauth_authorize -->|
   |                                          | state + PKCE verifier (random)
   |<-- 302 + cookie esnacc_oauth (signed, 10 min, state + verifier)
   |-- GET /oauth/authorize?response_type=code&client_id&redirect_uri&scope&state&code_challenge(S256) -->|
   |                                   (the user signs in on ESN Accounts and allows the access)          |
   |<-- 302 /<stage>/esnacc_oauth_callback?code&state (or ?error=access_denied) --------------------------|
   |-- GET /<stage>/esnacc_oauth_callback ---->|
   |                                          | check cookie + state (constant time)
   |                                          |-- POST /oauth/token (code, verifier, same redirect_uri) -->|
   |                                          |-- GET /oauth/v2/userinfo (Bearer) ------------------------>|
   |                                          |-- GET /api/v2/sections, /api/v2/countries (cached) ------->|
   |                                          | map the profile to the platform's user;
   |                                          | sign the platform's JWT (as the CAS login does)
   |<-- 302 https://<front-end>/auth?token=<JWT>   (or /auth?error=<code>); the cookie is deleted
```

The front-end stores the token exactly as for the CAS login (`front-end/src/app/auth/auth.page.ts`).

Code: `back-end/src/esnacc/` (configuration, PKCE/state/cookie, ESN Accounts calls, user mapping, sections and
countries directory), `back-end/src/handlers/esnaccOAuth.ts` (the Lambda function), `ESN_ACCOUNTS_ROLES_MAP` in
`back-end/src/models/user.model.ts` (roles) and `front-end/src/app/auth/` (buttons and error messages).

## URLs

**Every OAuth URL is derived from the stage's configuration**, in `back-end/deploy/environments.ts`; none is hardcoded
in the code and none is read from the request's headers (the spec warns against trusting forwarded hosts, and the
redirect URI must be byte-for-byte the registered one):

| URL                       | Built from                                                         | Dev value                                               |
| ------------------------- | ------------------------------------------------------------------ | ------------------------------------------------------- |
| ESN Accounts' endpoints   | `parameters.esnAccountsURL` (Lambda env. `ESN_ACCOUNTS_URL`)       | `https://accounts.esn.org/oauth/...`, `/api/v2/...`     |
| Redirect URI              | `https://${parameters.apiDomain}/${stage}/esnacc_oauth_callback`   | `https://api.assembly.esn.hu/dev/esnacc_oauth_callback` |
| Front-end return URL      | `https://${APP_DOMAIN}/auth` (stage domain, or prod custom domain) | `https://dev.assembly.esn.hu/auth`                      |
| Start of the flow         | front-end: `https://${parameters.apiDomain}/${stage}/...authorize` | `https://api.assembly.esn.hu/dev/esnacc_oauth_authorize` |

Why: since the external DNS switch, `main` builds every domain from `environments.ts` (`DOMAIN`, `api.`/`dev.` +
`DOMAIN`), and `DNS_MODE` (`external` or `route53`) changes who manages the DNS records, not the names. So moving to
another domain is still a one-line change, and the OAuth URLs follow it. Only the redirect URIs registered with ESN
Accounts have to be updated too.

Local development: with `?localhost=<port>` (added by the front-end when served on `localhost`), the flow ends on
`http://localhost:<port>/auth`; this is accepted only on the `dev` stage. The redirect URI doesn't change.

## The user

The OAuth user has the same shape as the CAS one, so the platform works the same way for both.

| User field              | From the userinfo                                                                                     |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| `userId`                | `preferred_username`, trimmed and lower-cased, as the CAS login does with the CAS username            |
| `email`                 | `esn_email` (as the CAS login), else `email`                                                          |
| `firstName`, `lastName` | `given_name`, `family_name` (else `name` split; the first name falls back to `nickname`, then userId) |
| `avatarURL`             | `picture`                                                                                             |
| `roles`                 | `groups` as returned (`<scope>:<role>`, e.g. `HU-BUPE-ELT:section-active_member`); array or object    |
| `sectionCode`           | the first section role (`<SECTION-CODE>:section-*`), else the first `detailed_groups` of type section |
| `section`               | the section's `label` in `/api/v2/sections` (e.g. "ESN ELTE"), else the `detailed_groups` label       |
| `country`               | the `label` in `/api/v2/countries` (e.g. "ESN Hungary") of the section's country or, without a section, of the first `<CC>:country-*` (then `<CC>:all`) role; empty if the directory is unavailable |
| `isAdministrator`, ...  | the platform's configurations, as for the CAS login (the first user ever becomes administrator)       |

**The user ID is `preferred_username`**, so the same person gets the same account with CAS and OAuth. `sub` and the
legacy identifiers (`sub_legacy`, `legacy_sub`) are never used. The sign-in is refused (`no_username`) if
`preferred_username` is missing or isn't a valid ESN Accounts username (control characters, more than 60 characters).

### Sections and countries

They are resolved through ESN Accounts' public directory (`/api/v2/sections`: ~600 sections, ~700 KB;
`/api/v2/countries`: ~50 countries), not guessed from strings. The two lists are loaded at sign-in time, in parallel
with the token exchange (3 s timeout), and kept in the Lambda's memory for 24 hours. If ESN Accounts is unavailable,
the last loaded lists are used; if there are none, the sign-in still succeeds (section from the userinfo, no country)
and a warning is logged; the next attempt is after 5 minutes. See `back-end/src/esnacc/directory.ts`.

## Roles

The platform's roles (used e.g. to restrict who can interact with a topic) recognise both the CAS and the OAuth roles,
following the official
[ESN Accounts - roles mapping](https://docs.google.com/spreadsheets/d/e/2PACX-1vRdzqFX1zRyOoAZxsrAWYxEuE0xs_0hX-8Jk10yAwEeC-WE81W2orTtkYjCPH-lrBsGu_lB-bbzlaKf/pubhtml)
sheet, which pairs each OAuth role with its CAS role. See `ESN_ACCOUNTS_ROLES_MAP` in
`back-end/src/models/user.model.ts`; matching is case-insensitive and `*` stands for any text.

| Platform role               | CAS roles                                                            | OAuth roles                                                                          |
| --------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `INTERNATIONAL_BOARD`       | `International.{president, vicePresident, treasurer, ...}`           | `INT:international-{board, president, vp_governance, vp_development, treasurer, communication, wpa}` |
| `INTERNATIONAL_SECRETARIAT` | `International.officeStaff`                                          | `INT:international-staff`                                                            |
| `INTERNATIONAL_GA_CT`       | `International.{agmchair, CNRadmin, CNRsecretary}`                   | `BODY:ga-{chair, administrator, secretary}`                                          |
| `INTERNATIONAL_AB`          | `International.AB.*`                                                 | `BODY:ab`, `BODY:ab-*`                                                               |
| `INTERNATIONAL_AC`          | `International.AC.*`                                                 | `BODY:ac`, `BODY:ac-*`                                                               |
| `INTERNATIONAL_LEVEL`       | `International.*`                                                    | `INT:*`, `BODY:*`, `COMMITTEE:*`, `COMMITEE:*` (both spellings are in the sheet), `TEAM:*` |
| `NATIONAL_BOARD`            | `National.regularBoardMember`                                        | `<COUNTRY-CODE>:country-regular_board_member`                                        |
| `NATIONAL_LEVEL`            | `National.*`                                                         | `<COUNTRY-CODE>:country-*`                                                           |
| `LOCAL_BOARD`               | `Local.regularBoardMember`                                           | `<SECTION-CODE>:section-regular_board_member`                                        |
| `LOCAL_LEVEL`               | `Local.*`                                                            | `<SECTION-CODE>:section-*`                                                           |

Generic memberships (`<COUNTRY-CODE>:all`, `<SECTION-CODE>:all`, `<RP>:member`, e.g. `CEP:member`) and the tools'
permissions (`PERMISSIONS:*`) grant no platform role, as their CAS counterparts didn't. The "regular board member"
role is, according to the sheet, assigned to all the board members of a section/NO.

## Session length

| What                                  | Lifetime    | Where                                                       |
| ------------------------------------- | ----------- | ----------------------------------------------------------- |
| Platform JWT of **OAuth** sign-ins    | **7 days**  | `OAUTH_JWT_EXPIRE_TIME` in `back-end/src/esnacc/config.ts`  |
| Platform JWT of CAS sign-ins          | 1 day       | `JWT_EXPIRE_TIME` in `back-end/src/handlers/login.ts`       |
| Flow cookie `esnacc_oauth`            | 10 minutes  | `OAUTH_COOKIE_MAX_AGE_SECONDS` in `back-end/src/esnacc/config.ts` |

The session is the JWT, not a cookie: the front-end stores it with its expiry (`tokenExpiresAt`, from the JWT's `exp`)
and asks for a new sign-in after it (`front-end/src/app/auth.guard.ts`); the API's authorizer rejects expired tokens.
Roles, section and country in the token are refreshed at the next sign-in; the administrator/manager permissions are
checked at every request. The flow cookie (HttpOnly, Secure, SameSite=Lax, scoped to the callback, HMAC-signed with a
key derived from the platform's secret) only carries `state` and the PKCE verifier during the sign-in, and is deleted
by the callback.

## Errors

On failure, the user is sent back to the sign-in page (`/auth?error=<code>`), where a translated message is shown
(`AUTH.OAUTH_ERRORS.*` in `front-end/src/assets/i18n/en.json`).

| Code              | Meaning                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------ |
| `access_denied`   | The user cancelled or denied the access on ESN Accounts                                    |
| `invalid_request` | ESN Accounts returned another error, or no authorization code                              |
| `invalid_state`   | The flow's cookie is missing, expired (10 minutes) or tampered with, or `state` differs    |
| `esnacc_error`    | The token or userinfo endpoint of ESN Accounts failed (error, timeout, invalid answer)     |
| `no_username`     | The profile has no valid `preferred_username`                                              |
| `generic`         | Anything else (e.g. the client's credentials are missing in AWS SSM)                       |

## Logs

Tokens, the client secret, the authorization code and `state` are never logged (code and state are redacted from
the request log). On `dev` (`logLevel: DEBUG`) the Lambda function `esn-assembly-hu_dev_esnaccOAuth` logs the names
(and types) of the userinfo's claims and the mapped values (user ID, roles, section, country); in production only the
user ID of each sign-in and the error codes are logged.

## Set up

1. **Register the OAuth client with ESN Accounts**, with one redirect URI per stage, exactly:
   - `https://api.assembly.esn.hu/dev/esnacc_oauth_callback`
   - `https://api.assembly.esn.hu/prod/esnacc_oauth_callback` (for the prod rollout)

   Scope: `oauth2_access_to_profile_information`. The same client is used by both stages.

2. **Store the client's credentials in AWS Systems Manager** (Parameter Store, `SecureString`), next to the
   platform's `/esn-assembly-hu/auth` secret. Never commit them:

   ```sh
   aws ssm put-parameter --profile esn-assembly-hu --type "SecureString" --name "/esn-assembly-hu/esnacc-oauth" \
     --value '{"clientId":"<CLIENT_ID>","clientSecret":"<CLIENT_SECRET>"}'
   ```

   Add `--overwrite` to change existing credentials; the Lambda functions cache them while warm, so redeploy (or wait
   for new instances) afterwards.

3. **Deploy** the back-end of the stage and release its front-end, as usual (see `HOW-TO-DEPLOY.md`):

   ```sh
   cd back-end && bash deploy.sh dev
   cd ../front-end && bash release.sh dev
   ```

   The front-end targets the API stage set by `STAGE` in `front-end/src/environments/environment.idea.ts`.

## Tests

```sh
cd back-end
npm test
```

They cover PKCE and `state`, the flow cookie, the callback and its error paths against a fake ESN Accounts (the
spec's acceptance tests), the user mapping, the roles of the sheet and the sections/countries directory.

Manual test on a deployed stage: CAS still works; the OAuth sign-in works and gives the same `userId` as CAS for the
same person, with the right roles, section and country; the Google button shows "Function coming soon!"; cancelling
on ESN Accounts shows the "cancelled" message; using the callback after 10 minutes (or without the cookie) shows the
"expired" message; the session lasts 7 days (check `tokenExpiresAt` in the browser's storage).
