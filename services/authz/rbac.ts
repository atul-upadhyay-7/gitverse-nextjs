import { RepositoryRole } from "../../types/repository-permissions";

export type Permission =
  | "policy:read"
  | "policy:write"
  | "policy:delete"
  | "repository:read"
  | "repository:write"
  | "repository:admin"
  | "organization:read"
  | "organization:write"
  | "organization:admin"
  | "analysis:read"
  | "analysis:write"
  | "analysis:delete"
  | "webhook:read"
  | "webhook:write"
  | "webhook:delete"
  | "member:read"
  | "member:write"
  | "member:delete"
  | "settings:read"
  | "settings:write";

const ROLE_PERMISSIONS: Record<RepositoryRole, Set<Permission>> = {
  ORG_ADMIN: new Set([
    "policy:read",
    "policy:write",
    "policy:delete",
    "repository:read",
    "repository:write",
    "repository:admin",
    "organization:read",
    "organization:write",
    "organization:admin",
    "analysis:read",
    "analysis:write",
    "analysis:delete",
    "webhook:read",
    "webhook:write",
    "webhook:delete",
    "member:read",
    "member:write",
    "member:delete",
    "settings:read",
    "settings:write",
  ]),
  REPO_ADMIN: new Set([
    "policy:read",
    "policy:write",
    "repository:read",
    "repository:write",
    "analysis:read",
    "analysis:write",
    "analysis:delete",
    "webhook:read",
    "webhook:write",
  ]),
  CONTRIBUTOR: new Set([
    "policy:read",
    "repository:read",
    "repository:write",
    "analysis:read",
    "analysis:write",
  ]),
  VIEWER: new Set([
    "policy:read",
    "repository:read",
    "analysis:read",
  ]),
};

const ROLE_HIERARCHY: Record<RepositoryRole, number> = {
  ORG_ADMIN: 4,
  REPO_ADMIN: 3,
  CONTRIBUTOR: 2,
  VIEWER: 1,
};

const POLICY_MODIFY_ROLES: RepositoryRole[] = ["ORG_ADMIN", "REPO_ADMIN"];
const POLICY_READ_ROLES: RepositoryRole[] = [
  "ORG_ADMIN",
  "REPO_ADMIN",
  "CONTRIBUTOR",
  "VIEWER",
];

export class RBAC {
  /**
   * Verifies if a role has permission to modify repository policies.
   */
  static canModifyPolicy(role: RepositoryRole): boolean {
    return POLICY_MODIFY_ROLES.includes(role);
  }

  /**
   * Verifies if a role has permission to read repository policies.
   */
  static canReadPolicy(role: RepositoryRole): boolean {
    return POLICY_READ_ROLES.includes(role);
  }

  /**
   * Checks if a role has a specific permission.
   */
  static hasPermission(role: RepositoryRole, permission: Permission): boolean {
    const perms = ROLE_PERMISSIONS[role];
    if (!perms) return false;
    return perms.has(permission);
  }

  /**
   * Checks if a role has all of the specified permissions.
   */
  static hasAllPermissions(
    role: RepositoryRole,
    permissions: Permission[]
  ): boolean {
    return permissions.every((p) => this.hasPermission(role, p));
  }

  /**
   * Checks if a role has any of the specified permissions.
   */
  static hasAnyPermission(
    role: RepositoryRole,
    permissions: Permission[]
  ): boolean {
    return permissions.some((p) => this.hasPermission(role, p));
  }

  /**
   * Returns all permissions for a given role.
   */
  static getPermissions(role: RepositoryRole): Permission[] {
    const perms = ROLE_PERMISSIONS[role];
    if (!perms) return [];
    return Array.from(perms);
  }

  /**
   * Compares two roles and returns true if the user role has equal or higher
   * privilege than the required role.
   */
  static hasMinimumRole(
    userRole: RepositoryRole,
    minimumRole: RepositoryRole
  ): boolean {
    const userLevel = ROLE_HIERARCHY[userRole] || 0;
    const requiredLevel = ROLE_HIERARCHY[minimumRole] || 0;
    return userLevel >= requiredLevel;
  }

  /**
   * Checks if a string is a valid RepositoryRole.
   */
  static isValidRole(role: string): role is RepositoryRole {
    return role in ROLE_PERMISSIONS;
  }

  /**
   * Returns all valid roles.
   */
  static getValidRoles(): RepositoryRole[] {
    return Object.keys(ROLE_PERMISSIONS) as RepositoryRole[];
  }
}
