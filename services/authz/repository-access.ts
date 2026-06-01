import prisma from "../../lib/prisma";
import { RepositoryAccessResult, RepositoryRole } from "../../types/repository-permissions";

const VALID_ROLES = new Set<RepositoryRole>([
  "ORG_ADMIN",
  "REPO_ADMIN",
  "CONTRIBUTOR",
  "VIEWER",
]);

const ROLE_HIERARCHY: Record<RepositoryRole, number> = {
  ORG_ADMIN: 4,
  REPO_ADMIN: 3,
  CONTRIBUTOR: 2,
  VIEWER: 1,
};

/**
 * Validates that a string is a known RepositoryRole.
 * Returns the validated role or null if invalid.
 */
function validateRole(role: string | null | undefined): RepositoryRole | null {
  if (!role || typeof role !== "string") return null;
  if (!VALID_ROLES.has(role as RepositoryRole)) return null;
  return role as RepositoryRole;
}

/**
 * Checks if the user's role grants at least the required permission level.
 */
function hasMinimumRole(userRole: RepositoryRole, minimumRole: RepositoryRole): boolean {
  return (ROLE_HIERARCHY[userRole] || 0) >= (ROLE_HIERARCHY[minimumRole] || 0);
}

export class RepositoryAccess {
  /**
   * Validates a user's access rights to a repository.
   * Performs repository checks, ownership lookups, and organization-level RBAC role retrieval.
   *
   * Security: Role values from the database are validated against the allowed
   * set before being returned. Unknown roles are treated as VIEWER (least privilege)
   * to prevent privilege escalation via data corruption or manipulation.
   */
  public static async checkAccess(
    repositoryId: number,
    userId: number
  ): Promise<RepositoryAccessResult> {
    try {
      // 1. Retrieve the repository
      const repository = await prisma.repository.findUnique({
        where: { id: repositoryId },
        select: { id: true, userId: true },
      });

      if (!repository) {
        return {
          allowed: false,
          repositoryExists: false,
          reason: "Repository not found",
        };
      }

      // 2. Personal ownership verification
      if (repository.userId === userId) {
        return {
          allowed: true,
          role: "REPO_ADMIN",
          repositoryExists: true,
        };
      }

      // 3. Organization association lookup
      const assignment = await prisma.repositoryPolicyAssignment.findUnique({
        where: { repositoryId },
        select: { organizationId: true },
      });

      if (!assignment) {
        // No organization assigned and user is not direct owner
        return {
          allowed: false,
          repositoryExists: true,
          reason: "Unauthorized access to repository",
        };
      }

      // 4. Organization membership check
      const membership = await prisma.organizationMember.findUnique({
        where: {
          organizationId_userId: {
            organizationId: assignment.organizationId,
            userId,
          },
        },
        select: { role: true },
      });

      if (!membership) {
        return {
          allowed: false,
          repositoryExists: true,
          reason: "User is not a member of the repository organization",
        };
      }

      // 5. Validate role from database — reject unknown values
      const role = validateRole(membership.role);

      if (!role) {
        // Unknown role in database — log the anomaly and deny access
        console.error(
          `[RepositoryAccess] CRITICAL: User ${userId} has invalid role "${membership.role}" ` +
          `in organization ${assignment.organizationId}. Denying access as precaution.`
        );
        return {
          allowed: false,
          repositoryExists: true,
          reason: "Invalid role configuration. Contact your organization administrator.",
        };
      }

      return {
        allowed: true,
        role,
        repositoryExists: true,
      };
    } catch (error: any) {
      console.error("[RepositoryAccess] Error checking access rights:", error);
      return {
        allowed: false,
        repositoryExists: true,
        reason: `Authorization error: ${error.message || error}`,
      };
    }
  }

  /**
   * Checks if a user has at least the specified role level for a repository.
   * Convenience method for role-based authorization checks.
   */
  public static async hasMinimumRole(
    repositoryId: number,
    userId: number,
    minimumRole: RepositoryRole
  ): Promise<boolean> {
    const result = await this.checkAccess(repositoryId, userId);
    if (!result.allowed || !result.role) return false;
    return hasMinimumRole(result.role, minimumRole);
  }

  /**
   * Returns the list of valid repository roles.
   */
  static getValidRoles(): RepositoryRole[] {
    return Array.from(VALID_ROLES);
  }

  /**
   * Checks if a given string is a valid repository role.
   */
  static isValidRole(role: string): role is RepositoryRole {
    return VALID_ROLES.has(role as RepositoryRole);
  }
}
