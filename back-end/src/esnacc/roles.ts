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

  const groups = userInfo.groups && typeof userInfo.groups === 'object' ? userInfo.groups : {};
  for (const [groupId, role] of Object.entries(groups)) {
    if (typeof role !== 'string') continue;

    roles.push({
      role,
      source: 'groups',
      group: groupId
    });
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
