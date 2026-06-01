/**
 * Tests for RepositoryAccess service.
 * Validates role validation, access control, and security against
 * privilege escalation via invalid database role values.
 */

jest.mock("../../../lib/prisma", () => ({
  __esModule: true,
  default: {
    repository: {
      findUnique: jest.fn(),
    },
    repositoryPolicyAssignment: {
      findUnique: jest.fn(),
    },
    organizationMember: {
      findUnique: jest.fn(),
    },
  },
}));

import { RepositoryAccess } from "../../../services/authz/repository-access";
import prisma from "../../../lib/prisma";

describe("RepositoryAccess", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("checkAccess", () => {
    it("returns REPO_ADMIN for repository owner", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });

      const result = await RepositoryAccess.checkAccess(1, 100);

      expect(result.allowed).toBe(true);
      expect(result.role).toBe("REPO_ADMIN");
    });

    it("returns not found for non-existent repository", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await RepositoryAccess.checkAccess(999, 100);

      expect(result.allowed).toBe(false);
      expect(result.repositoryExists).toBe(false);
    });

    it("denies access when user is not owner and no org assignment", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.repositoryExists).toBe(true);
      expect(result.reason).toContain("Unauthorized");
    });

    it("denies access when user is not org member", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("not a member");
    });

    it("allows access with valid role from database", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "CONTRIBUTOR",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(true);
      expect(result.role).toBe("CONTRIBUTOR");
    });

    it("allows access with ORG_ADMIN role", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "ORG_ADMIN",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(true);
      expect(result.role).toBe("ORG_ADMIN");
    });

    it("denies access for unknown role (privilege escalation prevention)", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "SUPER_ADMIN",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Invalid role");
      expect(console.error).toHaveBeenCalled();
    });

    it("denies access for empty role string", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Invalid role");
    });

    it("denies access for null role", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: null,
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Invalid role");
    });

    it("denies access for numeric role", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: 42,
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
    });

    it("denies access for role with SQL injection attempt", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "'; DROP TABLE users; --",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Invalid role");
    });

    it("denies access for role with path traversal", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "../../../admin",
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
    });

    it("denies access for role with XSS attempt", async () => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: '<script>alert("xss")</script>',
      });

      const result = await RepositoryAccess.checkAccess(1, 200);

      expect(result.allowed).toBe(false);
    });

    it("handles DB errors gracefully", async () => {
      (prisma.repository.findUnique as jest.Mock).mockRejectedValue(
        new Error("DB connection failed")
      );

      const result = await RepositoryAccess.checkAccess(1, 100);

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain("Authorization error");
    });
  });

  describe("hasMinimumRole", () => {
    beforeEach(() => {
      (prisma.repository.findUnique as jest.Mock).mockResolvedValue({
        id: 1,
        userId: 100,
      });
      (prisma.repositoryPolicyAssignment.findUnique as jest.Mock).mockResolvedValue({
        organizationId: "org-1",
      });
    });

    it("returns true when user has higher role", async () => {
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "ORG_ADMIN",
      });

      expect(await RepositoryAccess.hasMinimumRole(1, 200, "VIEWER")).toBe(true);
    });

    it("returns true when user has exact role", async () => {
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "CONTRIBUTOR",
      });

      expect(await RepositoryAccess.hasMinimumRole(1, 200, "CONTRIBUTOR")).toBe(true);
    });

    it("returns false when user has lower role", async () => {
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "VIEWER",
      });

      expect(await RepositoryAccess.hasMinimumRole(1, 200, "CONTRIBUTOR")).toBe(false);
    });

    it("returns false for invalid role in database", async () => {
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue({
        role: "HACKED_ROLE",
      });

      expect(await RepositoryAccess.hasMinimumRole(1, 200, "VIEWER")).toBe(false);
    });

    it("returns false when user is not a member", async () => {
      (prisma.organizationMember.findUnique as jest.Mock).mockResolvedValue(null);

      expect(await RepositoryAccess.hasMinimumRole(1, 200, "VIEWER")).toBe(false);
    });
  });

  describe("getValidRoles", () => {
    it("returns exactly 4 roles", () => {
      expect(RepositoryAccess.getValidRoles()).toHaveLength(4);
    });
  });

  describe("isValidRole", () => {
    it("validates correct roles", () => {
      expect(RepositoryAccess.isValidRole("ORG_ADMIN")).toBe(true);
      expect(RepositoryAccess.isValidRole("REPO_ADMIN")).toBe(true);
      expect(RepositoryAccess.isValidRole("CONTRIBUTOR")).toBe(true);
      expect(RepositoryAccess.isValidRole("VIEWER")).toBe(true);
    });

    it("rejects invalid roles", () => {
      expect(RepositoryAccess.isValidRole("SUPER_ADMIN")).toBe(false);
      expect(RepositoryAccess.isValidRole("admin")).toBe(false);
      expect(RepositoryAccess.isValidRole("")).toBe(false);
      expect(RepositoryAccess.isValidRole("ROOT")).toBe(false);
    });
  });
});
