/**
 * Tests for RBAC (Role-Based Access Control) service.
 * Validates role hierarchy, permission checks, and role validation.
 */

import { RBAC, Permission } from "../../../services/authz/rbac";
import { RepositoryRole } from "../../../types/repository-permissions";

describe("RBAC", () => {
  describe("canModifyPolicy", () => {
    it("allows ORG_ADMIN to modify policies", () => {
      expect(RBAC.canModifyPolicy("ORG_ADMIN")).toBe(true);
    });

    it("allows REPO_ADMIN to modify policies", () => {
      expect(RBAC.canModifyPolicy("REPO_ADMIN")).toBe(true);
    });

    it("denies CONTRIBUTOR from modifying policies", () => {
      expect(RBAC.canModifyPolicy("CONTRIBUTOR")).toBe(false);
    });

    it("denies VIEWER from modifying policies", () => {
      expect(RBAC.canModifyPolicy("VIEWER")).toBe(false);
    });
  });

  describe("canReadPolicy", () => {
    it("allows all roles to read policies", () => {
      expect(RBAC.canReadPolicy("ORG_ADMIN")).toBe(true);
      expect(RBAC.canReadPolicy("REPO_ADMIN")).toBe(true);
      expect(RBAC.canReadPolicy("CONTRIBUTOR")).toBe(true);
      expect(RBAC.canReadPolicy("VIEWER")).toBe(true);
    });
  });

  describe("hasPermission", () => {
    it("ORG_ADMIN has all permissions", () => {
      const orgAdminPerms = RBAC.getPermissions("ORG_ADMIN");
      expect(orgAdminPerms.length).toBeGreaterThan(10);
      orgAdminPerms.forEach((perm) => {
        expect(RBAC.hasPermission("ORG_ADMIN", perm)).toBe(true);
      });
    });

    it("VIEWER has only read permissions", () => {
      expect(RBAC.hasPermission("VIEWER", "repository:read")).toBe(true);
      expect(RBAC.hasPermission("VIEWER", "analysis:read")).toBe(true);
      expect(RBAC.hasPermission("VIEWER", "policy:read")).toBe(true);
      expect(RBAC.hasPermission("VIEWER", "repository:write")).toBe(false);
      expect(RBAC.hasPermission("VIEWER", "repository:admin")).toBe(false);
      expect(RBAC.hasPermission("VIEWER", "member:delete")).toBe(false);
    });

    it("CONTRIBUTOR can write but not admin", () => {
      expect(RBAC.hasPermission("CONTRIBUTOR", "repository:write")).toBe(true);
      expect(RBAC.hasPermission("CONTRIBUTOR", "analysis:write")).toBe(true);
      expect(RBAC.hasPermission("CONTRIBUTOR", "repository:admin")).toBe(false);
      expect(RBAC.hasPermission("CONTRIBUTOR", "organization:admin")).toBe(false);
    });

    it("REPO_ADMIN can manage repo but not organization", () => {
      expect(RBAC.hasPermission("REPO_ADMIN", "repository:write")).toBe(true);
      expect(RBAC.hasPermission("REPO_ADMIN", "analysis:delete")).toBe(true);
      expect(RBAC.hasPermission("REPO_ADMIN", "organization:admin")).toBe(false);
      expect(RBAC.hasPermission("REPO_ADMIN", "member:delete")).toBe(false);
    });
  });

  describe("hasAllPermissions", () => {
    it("returns true when role has all permissions", () => {
      expect(
        RBAC.hasAllPermissions("ORG_ADMIN", ["policy:read", "policy:write", "member:delete"])
      ).toBe(true);
    });

    it("returns false when role lacks any permission", () => {
      expect(
        RBAC.hasAllPermissions("VIEWER", ["repository:read", "repository:write"])
      ).toBe(false);
    });

    it("returns true for empty permission list", () => {
      expect(RBAC.hasAllPermissions("VIEWER", [])).toBe(true);
    });
  });

  describe("hasAnyPermission", () => {
    it("returns true when role has at least one permission", () => {
      expect(
        RBAC.hasAnyPermission("VIEWER", ["repository:write", "repository:read"])
      ).toBe(true);
    });

    it("returns false when role has none of the permissions", () => {
      expect(
        RBAC.hasAnyPermission("VIEWER", ["repository:write", "member:delete"])
      ).toBe(false);
    });

    it("returns false for empty permission list", () => {
      expect(RBAC.hasAnyPermission("ORG_ADMIN", [])).toBe(false);
    });
  });

  describe("hasMinimumRole", () => {
    it("ORG_ADMIN meets all minimums", () => {
      expect(RBAC.hasMinimumRole("ORG_ADMIN", "VIEWER")).toBe(true);
      expect(RBAC.hasMinimumRole("ORG_ADMIN", "CONTRIBUTOR")).toBe(true);
      expect(RBAC.hasMinimumRole("ORG_ADMIN", "REPO_ADMIN")).toBe(true);
      expect(RBAC.hasMinimumRole("ORG_ADMIN", "ORG_ADMIN")).toBe(true);
    });

    it("VIEWER meets only VIEWER minimum", () => {
      expect(RBAC.hasMinimumRole("VIEWER", "VIEWER")).toBe(true);
      expect(RBAC.hasMinimumRole("VIEWER", "CONTRIBUTOR")).toBe(false);
      expect(RBAC.hasMinimumRole("VIEWER", "REPO_ADMIN")).toBe(false);
      expect(RBAC.hasMinimumRole("VIEWER", "ORG_ADMIN")).toBe(false);
    });

    it("REPO_ADMIN meets VIEWER and CONTRIBUTOR minimums", () => {
      expect(RBAC.hasMinimumRole("REPO_ADMIN", "VIEWER")).toBe(true);
      expect(RBAC.hasMinimumRole("REPO_ADMIN", "CONTRIBUTOR")).toBe(true);
      expect(RBAC.hasMinimumRole("REPO_ADMIN", "REPO_ADMIN")).toBe(true);
      expect(RBAC.hasMinimumRole("REPO_ADMIN", "ORG_ADMIN")).toBe(false);
    });

    it("CONTRIBUTOR meets VIEWER minimum only", () => {
      expect(RBAC.hasMinimumRole("CONTRIBUTOR", "VIEWER")).toBe(true);
      expect(RBAC.hasMinimumRole("CONTRIBUTOR", "CONTRIBUTOR")).toBe(true);
      expect(RBAC.hasMinimumRole("CONTRIBUTOR", "REPO_ADMIN")).toBe(false);
    });
  });

  describe("isValidRole", () => {
    it("accepts valid roles", () => {
      expect(RBAC.isValidRole("ORG_ADMIN")).toBe(true);
      expect(RBAC.isValidRole("REPO_ADMIN")).toBe(true);
      expect(RBAC.isValidRole("CONTRIBUTOR")).toBe(true);
      expect(RBAC.isValidRole("VIEWER")).toBe(true);
    });

    it("rejects invalid roles", () => {
      expect(RBAC.isValidRole("SUPER_ADMIN")).toBe(false);
      expect(RBAC.isValidRole("admin")).toBe(false);
      expect(RBAC.isValidRole("")).toBe(false);
      expect(RBAC.isValidRole("ROLE_ADMIN")).toBe(false);
    });
  });

  describe("getValidRoles", () => {
    it("returns exactly 4 roles", () => {
      expect(RBAC.getValidRoles()).toHaveLength(4);
    });

    it("includes all expected roles", () => {
      const roles = RBAC.getValidRoles();
      expect(roles).toContain("ORG_ADMIN");
      expect(roles).toContain("REPO_ADMIN");
      expect(roles).toContain("CONTRIBUTOR");
      expect(roles).toContain("VIEWER");
    });
  });

  describe("getPermissions", () => {
    it("returns permissions for each role", () => {
      expect(RBAC.getPermissions("ORG_ADMIN").length).toBeGreaterThan(
        RBAC.getPermissions("REPO_ADMIN").length
      );
      expect(RBAC.getPermissions("REPO_ADMIN").length).toBeGreaterThan(
        RBAC.getPermissions("CONTRIBUTOR").length
      );
      expect(RBAC.getPermissions("CONTRIBUTOR").length).toBeGreaterThan(
        RBAC.getPermissions("VIEWER").length
      );
    });

    it("permissions are unique per role", () => {
      for (const role of RBAC.getValidRoles()) {
        const perms = RBAC.getPermissions(role);
        expect(new Set(perms).size).toBe(perms.length);
      }
    });
  });

  describe("permission hierarchy integrity", () => {
    it("each higher role has strictly more permissions than the lower", () => {
      const viewPerms = new Set(RBAC.getPermissions("VIEWER"));
      const contribPerms = new Set(RBAC.getPermissions("CONTRIBUTOR"));
      const repoAdminPerms = new Set(RBAC.getPermissions("REPO_ADMIN"));
      const orgAdminPerms = new Set(RBAC.getPermissions("ORG_ADMIN"));

      // CONTRIBUTOR has all VIEWER permissions plus more
      for (const p of viewPerms) {
        expect(contribPerms.has(p)).toBe(true);
      }
      expect(contribPerms.size).toBeGreaterThan(viewPerms.size);

      // REPO_ADMIN has all CONTRIBUTOR permissions plus more
      for (const p of contribPerms) {
        expect(repoAdminPerms.has(p)).toBe(true);
      }
      expect(repoAdminPerms.size).toBeGreaterThan(contribPerms.size);

      // ORG_ADMIN has all REPO_ADMIN permissions plus more
      for (const p of repoAdminPerms) {
        expect(orgAdminPerms.has(p)).toBe(true);
      }
      expect(orgAdminPerms.size).toBeGreaterThan(repoAdminPerms.size);
    });
  });
});
