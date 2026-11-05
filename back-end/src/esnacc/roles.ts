/**
 * Role extraction from the userinfo (port of `src/roles.ts` of ESN-Hungary/esnscope, spec section 7).
 */

import { ESNDetailedRole, RoleEntry, UserInfo } from './types';

/**
 * Extract every role, from both the flat OAuth `groups` and the (deprecated CAS) `detailed_groups`.
 * Roles are not deduplicated: the same role can legitimately appear in multiple groups or scopes.
 */
export function extractRoles(userInfo: UserInfo): RoleEntry[] {
  const roles: RoleEntry[] = [];

  if (Array.isArray(userInfo.groups)) {
    // the format returned by ESN Accounts: a list of `<scope>:<role>`, e.g. `RO-TIMI-ESN:section-active_member`
    for (const scopedRole of userInfo.groups) {
      if (typeof scopedRole !== 'string') continue;

      const separatorIndex = scopedRole.indexOf(':');
      if (separatorIndex > 0) {
        const scope = scopedRole.slice(0, separatorIndex);
        roles.push({ role: scopedRole.slice(separatorIndex + 1), source: 'groups', group: scope, scope });
      } else roles.push({ role: scopedRole, source: 'groups' });
    }
  } else if (userInfo.groups && typeof userInfo.groups === 'object') {
    // the format described by the spec: the key is the group ID, the value is the role
    for (const [groupId, role] of Object.entries(userInfo.groups)) {
      if (typeof role !== 'string') continue;

      roles.push({
        role,
        source: 'groups',
        group: groupId
      });
    }
  }

  const detailedGroups = Array.isArray(userInfo.detailed_groups) ? userInfo.detailed_groups : [];
  for (const group of detailedGroups) {
    if (!group) continue;

    let detailedRoles: ESNDetailedRole[];
    if (Array.isArray(group.roles)) detailedRoles = group.roles;
    else if (group.roles && typeof group.roles === 'object') detailedRoles = [group.roles];
    else detailedRoles = [];

    for (const detailedRole of detailedRoles) {
      if (!detailedRole || typeof detailedRole.role !== 'string') continue;

      roles.push({
        role: detailedRole.role,
        label: detailedRole.label,
        source: 'detailed_groups',
        group: group.label,
        type: group.type,
        scope: group.scope
      });
    }
  }

  return roles;
}
