/**
 * @jest-environment node
 *
 * Comprehensive tests for QuotaService
 *
 * Tests cover:
 * - Input validation for all public methods
 * - Rate limiting: under/at limit, race conditions, DB failures
 * - Quota management: atomic reservation, window expiry, env config
 * - Token tracking, warning state management
 * - Bulk operations, status queries, key sanitization
 * - Edge cases: boundary values, invalid inputs, error recovery
 */

jest.mock("@/lib/prisma", () => {
  return {
    __esModule: true,
    default: {
      rateLimit: {
        count: jest.fn().mockResolvedValue(0),
        create: jest.fn().mockResolvedValue({}),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      aiQuota: {
        findUnique: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
        upsert: jest.fn().mockResolvedValue({}),
        update: jest.fn().mockResolvedValue({}),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
        create: jest.fn().mockResolvedValue({}),
      },
    },
  };
});

import { QuotaService, QuotaStatus, RateLimitStatus } from "../quotaService";
import prisma from "@/lib/prisma";

describe("QuotaService", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(console, "error").mockImplementation(() => {});
    jest.spyOn(console, "warn").mockImplementation(() => {});

    (prisma.rateLimit.count as jest.Mock).mockReset();
    (prisma.rateLimit.create as jest.Mock).mockReset();
    (prisma.rateLimit.deleteMany as jest.Mock).mockReset().mockResolvedValue({ count: 0 });
    (prisma.aiQuota.findUnique as jest.Mock).mockReset();
    (prisma.aiQuota.findMany as jest.Mock).mockReset();
    (prisma.aiQuota.upsert as jest.Mock).mockReset();
    (prisma.aiQuota.update as jest.Mock).mockReset();
    (prisma.aiQuota.updateMany as jest.Mock).mockReset();

    process.env = { ...originalEnv };
    delete process.env.AI_QUOTA_PER_WINDOW;
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
    process.env = originalEnv;
  });

  // =========================================================================
  // Input Validation
  // =========================================================================

  describe("validateRateLimitParams", () => {
    it("returns null for valid parameters", () => {
      const result = QuotaService.validateRateLimitParams("webhook:123", 10, 60000);
      expect(result).toBeNull();
    });

    it("rejects non-string key", () => {
      const result = QuotaService.validateRateLimitParams(123 as any, 10, 60000);
      expect(result).toBe("Rate limit key must be a string");
    });

    it("rejects empty key", () => {
      const result = QuotaService.validateRateLimitParams("", 10, 60000);
      expect(result).toBe("Rate limit key must not be empty");
    });

    it("rejects key exceeding max length", () => {
      const result = QuotaService.validateRateLimitParams("a".repeat(256), 10, 60000);
      expect(result).toContain("must not exceed");
    });

    it("accepts key at max length", () => {
      const result = QuotaService.validateRateLimitParams("a".repeat(255), 10, 60000);
      expect(result).toBeNull();
    });

    it("rejects non-integer limit", () => {
      const result = QuotaService.validateRateLimitParams("key", 10.5, 60000);
      expect(result).toContain("positive integer");
    });

    it("rejects zero limit", () => {
      const result = QuotaService.validateRateLimitParams("key", 0, 60000);
      expect(result).toContain("greater than zero");
    });

    it("rejects negative limit", () => {
      const result = QuotaService.validateRateLimitParams("key", -5, 60000);
      expect(result).toContain("greater than zero");
    });

    it("rejects limit exceeding maximum", () => {
      const result = QuotaService.validateRateLimitParams("key", 100001, 60000);
      expect(result).toContain("must not exceed");
    });

    it("accepts limit at maximum", () => {
      const result = QuotaService.validateRateLimitParams("key", 100000, 60000);
      expect(result).toBeNull();
    });

    it("rejects non-finite window", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, Infinity);
      expect(result).toContain("finite number");
    });

    it("rejects NaN window", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, NaN);
      expect(result).toContain("finite number");
    });

    it("rejects window below minimum", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, 500);
      expect(result).toContain("at least");
    });

    it("rejects window exceeding maximum", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, 8 * 24 * 60 * 60 * 1000);
      expect(result).toContain("must not exceed");
    });

    it("accepts window at minimum", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, 1000);
      expect(result).toBeNull();
    });

    it("accepts window at maximum (7 days)", () => {
      const result = QuotaService.validateRateLimitParams("key", 10, 7 * 24 * 60 * 60 * 1000);
      expect(result).toBeNull();
    });
  });

  describe("validateInstallationId", () => {
    it("returns null for valid ID", () => {
      const result = QuotaService.validateInstallationId(BigInt(12345));
      expect(result).toBeNull();
    });

    it("rejects non-bigint", () => {
      const result = QuotaService.validateInstallationId(12345 as any);
      expect(result).toContain("BigInt");
    });

    it("rejects zero", () => {
      const result = QuotaService.validateInstallationId(0n);
      expect(result).toContain("positive");
    });

    it("rejects negative", () => {
      const result = QuotaService.validateInstallationId(-1n);
      expect(result).toContain("positive");
    });
  });

  describe("sanitizeKey", () => {
    it("removes control characters", () => {
      expect(QuotaService.sanitizeKey("key\x00\x1f\x7ftest")).toBe("keytest");
    });

    it("replaces whitespace with colons", () => {
      expect(QuotaService.sanitizeKey("key with spaces")).toBe("key:with:spaces");
    });

    it("trims leading and trailing whitespace", () => {
      expect(QuotaService.sanitizeKey("  key  ")).toBe("key");
    });

    it("strips tabs and newlines as control characters", () => {
      expect(QuotaService.sanitizeKey("key\t\nvalue")).toBe("keyvalue");
    });

    it("preserves normal characters", () => {
      expect(QuotaService.sanitizeKey("webhook:123:push")).toBe("webhook:123:push");
    });
  });

  // =========================================================================
  // Rate Limiting
  // =========================================================================

  describe("checkWebhookRateLimit", () => {
    it("allows request when under limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(0);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(true);
      expect(prisma.rateLimit.create).toHaveBeenCalledWith({
        data: expect.objectContaining({ key: "key1", points: 1 }),
      });
    });

    it("allows request at count one below limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(9);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(true);
    });

    it("rejects request when at limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(10);

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(false);
      expect(prisma.rateLimit.create).not.toHaveBeenCalled();
    });

    it("rejects request when over limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(15);

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(false);
    });

    it("handles unique constraint violation as rate-limited", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(9);
      (prisma.rateLimit.create as jest.Mock).mockRejectedValue(
        Object.assign(new Error("Unique constraint"), { code: "P2002" })
      );

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(false);
    });

    it("allows request when DB count fails (fail-open)", async () => {
      (prisma.rateLimit.count as jest.Mock).mockRejectedValue(
        new Error("Connection failed")
      );

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(true);
    });

    it("allows request when DB create fails with non-P2002 error (fail-open)", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(5);
      (prisma.rateLimit.create as jest.Mock).mockRejectedValue(
        new Error("Connection timeout")
      );

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(result).toBe(true);
    });

    it("triggers async cleanup of expired records", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(0);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});
      (prisma.rateLimit.deleteMany as jest.Mock).mockResolvedValue({ count: 5 });

      await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      // deleteMany is called with void (fire-and-forget), so we just verify
      // the mock was invoked
      expect(prisma.rateLimit.deleteMany).toHaveBeenCalled();
    });

    it("sanitizes key before querying", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(0);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      await QuotaService.checkWebhookRateLimit("key with spaces", 10, 60000);

      expect(prisma.rateLimit.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ key: "key:with:spaces" }),
        })
      );
    });

    it("rejects invalid parameters without querying DB", async () => {
      const result = await QuotaService.checkWebhookRateLimit("", 10, 60000);

      expect(result).toBe(false);
      expect(prisma.rateLimit.count).not.toHaveBeenCalled();
    });

    it("uses limit of 1 correctly", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(0);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.checkWebhookRateLimit("key1", 1, 60000);
      expect(result).toBe(true);

      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(1);
      const result2 = await QuotaService.checkWebhookRateLimit("key1", 1, 60000);
      expect(result2).toBe(false);
    });

    it("different keys have independent rate limits", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(10);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.checkWebhookRateLimit("key1", 10, 60000);
      expect(result).toBe(false);

      // The count mock is shared, but the implementation should use the key
      expect(prisma.rateLimit.count).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ key: "key1" }),
        })
      );
    });

    it("creates record with correct expiry time", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(0);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(prisma.rateLimit.create).toHaveBeenCalledWith({
        data: expect.objectContaining({
          expiresAt: new Date(now.getTime() + 60000),
        }),
      });
    });

    it("queries with correct expiry filter", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(3);
      (prisma.rateLimit.create as jest.Mock).mockResolvedValue({});

      await QuotaService.checkWebhookRateLimit("key1", 10, 60000);

      expect(prisma.rateLimit.count).toHaveBeenCalledWith({
        where: {
          key: "key1",
          expiresAt: { gte: now },
        },
      });
    });
  });

  // =========================================================================
  // Cleanup
  // =========================================================================

  describe("cleanupExpiredRateLimits", () => {
    it("deletes expired records and returns count", async () => {
      (prisma.rateLimit.deleteMany as jest.Mock).mockResolvedValue({ count: 42 });

      const result = await QuotaService.cleanupExpiredRateLimits();

      expect(result).toBe(42);
      expect(prisma.rateLimit.deleteMany).toHaveBeenCalledWith({
        where: { expiresAt: { lt: expect.any(Date) } },
      });
    });

    it("returns 0 on DB error", async () => {
      (prisma.rateLimit.deleteMany as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const result = await QuotaService.cleanupExpiredRateLimits();

      expect(result).toBe(0);
    });

    it("rejects batch size of 0", async () => {
      await expect(QuotaService.cleanupExpiredRateLimits(0)).rejects.toThrow(
        "Batch size must be between 1 and 10,000"
      );
    });

    it("rejects batch size exceeding maximum", async () => {
      await expect(QuotaService.cleanupExpiredRateLimits(10001)).rejects.toThrow(
        "Batch size must be between 1 and 10,000"
      );
    });

    it("accepts batch size at boundaries", async () => {
      (prisma.rateLimit.deleteMany as jest.Mock).mockResolvedValue({ count: 0 });

      const result1 = await QuotaService.cleanupExpiredRateLimits(1);
      expect(result1).toBe(0);

      const result2 = await QuotaService.cleanupExpiredRateLimits(10000);
      expect(result2).toBe(0);
    });
  });

  // =========================================================================
  // Rate Limit Status
  // =========================================================================

  describe("getRateLimitStatus", () => {
    it("returns current status when under limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(3);

      const status = await QuotaService.getRateLimitStatus("key1", 10, 60000);

      expect(status.currentCount).toBe(3);
      expect(status.remaining).toBe(7);
      expect(status.isExceeded).toBe(false);
      expect(status.utilizationPercent).toBe(30);
    });

    it("returns exceeded status when at limit", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(10);

      const status = await QuotaService.getRateLimitStatus("key1", 10, 60000);

      expect(status.currentCount).toBe(10);
      expect(status.remaining).toBe(0);
      expect(status.isExceeded).toBe(true);
      expect(status.utilizationPercent).toBe(100);
    });

    it("returns safe defaults on DB error", async () => {
      (prisma.rateLimit.count as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const status = await QuotaService.getRateLimitStatus("key1", 10, 60000);

      expect(status.currentCount).toBe(0);
      expect(status.remaining).toBe(10);
      expect(status.isExceeded).toBe(false);
      expect(status.utilizationPercent).toBe(0);
    });

    it("sanitizes key in status query", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(5);

      const status = await QuotaService.getRateLimitStatus("key with spaces", 10, 60000);

      expect(status.key).toBe("key:with:spaces");
    });

    it("calculates utilization correctly at various levels", async () => {
      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(1);

      const status1 = await QuotaService.getRateLimitStatus("key1", 10, 60000);
      expect(status1.utilizationPercent).toBe(10);

      (prisma.rateLimit.count as jest.Mock).mockResolvedValue(7);
      const status2 = await QuotaService.getRateLimitStatus("key1", 10, 60000);
      expect(status2.utilizationPercent).toBe(70);
    });
  });

  // =========================================================================
  // Quota Management
  // =========================================================================

  describe("getQuotaMax", () => {
    it("returns default of 250 when env not set", () => {
      delete process.env.AI_QUOTA_PER_WINDOW;
      expect(QuotaService.getQuotaMax()).toBe(250);
    });

    it("returns custom value from env", () => {
      process.env.AI_QUOTA_PER_WINDOW = "100";
      expect(QuotaService.getQuotaMax()).toBe(100);
    });

    it("returns default for invalid env value", () => {
      process.env.AI_QUOTA_PER_WINDOW = "abc";
      expect(QuotaService.getQuotaMax()).toBe(250);
    });

    it("returns default for negative env value", () => {
      process.env.AI_QUOTA_PER_WINDOW = "-5";
      expect(QuotaService.getQuotaMax()).toBe(250);
    });

    it("caps at maximum of 100,000", () => {
      process.env.AI_QUOTA_PER_WINDOW = "200000";
      expect(QuotaService.getQuotaMax()).toBe(100000);
    });

    it("accepts zero as invalid and returns default", () => {
      process.env.AI_QUOTA_PER_WINDOW = "0";
      expect(QuotaService.getQuotaMax()).toBe(250);
    });
  });

  describe("checkAndReserveQuota", () => {
    it("allows request when quota is available", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 0,
      });
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(true);
      expect(prisma.aiQuota.upsert).toHaveBeenCalled();
      expect(prisma.aiQuota.updateMany).toHaveBeenCalled();
    });

    it("rejects request when quota is exhausted", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 250,
      });
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 250,
        quotaWindowEnd: new Date(Date.now() + 86400000),
      });

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("resets window when expired and reserves", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 250,
      });
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 250,
        quotaWindowEnd: new Date(Date.now() - 1000),
      });
      (prisma.aiQuota.update as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(true);
      expect(prisma.aiQuota.update).toHaveBeenCalledWith({
        where: { id: "1" },
        data: expect.objectContaining({
          requestsUsed: 1,
          tokensConsumed: 0,
          warningPosted: false,
        }),
      });
    });

    it("returns false when quota record is null after upsert", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("fails closed on upsert DB errors", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockRejectedValue(
        new Error("DB connection failed")
      );

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("fails closed on updateMany DB errors", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});
      (prisma.aiQuota.updateMany as jest.Mock).mockRejectedValue(
        new Error("DB timeout")
      );

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("fails closed on findUnique DB errors during window check", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 0 });
      (prisma.aiQuota.findUnique as jest.Mock).mockRejectedValue(
        new Error("DB read error")
      );

      const result = await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("uses default max of 250 when env not set", async () => {
      delete process.env.AI_QUOTA_PER_WINDOW;
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 0,
      });
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(prisma.aiQuota.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ requestsUsed: { lt: 250 } }),
        })
      );
    });

    it("uses custom max from env", async () => {
      process.env.AI_QUOTA_PER_WINDOW = "100";
      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({
        id: "1",
        installationId: BigInt(1),
        requestsUsed: 0,
      });
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(prisma.aiQuota.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ requestsUsed: { lt: 100 } }),
        })
      );
    });

    it("rejects invalid installation ID", async () => {
      const result = await QuotaService.checkAndReserveQuota(0n);
      expect(result).toBe(false);
      expect(prisma.aiQuota.upsert).not.toHaveBeenCalled();
    });

    it("rejects negative installation ID", async () => {
      const result = await QuotaService.checkAndReserveQuota(-1n);
      expect(result).toBe(false);
    });

    it("creates quota record with correct fields for new installation", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      await QuotaService.checkAndReserveQuota(BigInt(42));

      expect(prisma.aiQuota.upsert).toHaveBeenCalledWith({
        where: { installationId: BigInt(42) },
        create: {
          installationId: BigInt(42),
          requestsUsed: 0,
          tokensConsumed: 0,
          quotaWindowStart: now,
          quotaWindowEnd: new Date(now.getTime() + 86400000),
          warningPosted: false,
        },
        update: {},
      });
    });

    it("sets lastAnalysisAt on successful reservation", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});
      (prisma.aiQuota.updateMany as jest.Mock).mockResolvedValue({ count: 1 });

      await QuotaService.checkAndReserveQuota(BigInt(1));

      expect(prisma.aiQuota.updateMany).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ lastAnalysisAt: now }),
        })
      );
    });
  });

  // =========================================================================
  // Token Usage
  // =========================================================================

  describe("recordTokenUsage", () => {
    it("increments token count", async () => {
      (prisma.aiQuota.update as jest.Mock).mockResolvedValue({});

      await QuotaService.recordTokenUsage(BigInt(1), 500);

      expect(prisma.aiQuota.update).toHaveBeenCalledWith({
        where: { installationId: BigInt(1) },
        data: { tokensConsumed: { increment: 500 } },
      });
    });

    it("handles zero tokens gracefully (no-op)", async () => {
      await QuotaService.recordTokenUsage(BigInt(1), 0);

      expect(prisma.aiQuota.update).not.toHaveBeenCalled();
    });

    it("rejects negative token count", async () => {
      await QuotaService.recordTokenUsage(BigInt(1), -100);

      expect(prisma.aiQuota.update).not.toHaveBeenCalled();
    });

    it("handles large token counts", async () => {
      (prisma.aiQuota.update as jest.Mock).mockResolvedValue({});

      await QuotaService.recordTokenUsage(BigInt(1), 1000000);

      expect(prisma.aiQuota.update).toHaveBeenCalledWith({
        where: { installationId: BigInt(1) },
        data: { tokensConsumed: { increment: 1000000 } },
      });
    });

    it("handles DB errors gracefully", async () => {
      (prisma.aiQuota.update as jest.Mock).mockRejectedValue(new Error("DB error"));

      await expect(
        QuotaService.recordTokenUsage(BigInt(1), 500)
      ).resolves.toBeUndefined();
    });
  });

  // =========================================================================
  // Warning State
  // =========================================================================

  describe("markWarningPosted", () => {
    it("sets warningPosted to true", async () => {
      (prisma.aiQuota.update as jest.Mock).mockResolvedValue({});

      await QuotaService.markWarningPosted(BigInt(1));

      expect(prisma.aiQuota.update).toHaveBeenCalledWith({
        where: { installationId: BigInt(1) },
        data: { warningPosted: true },
      });
    });

    it("handles errors gracefully", async () => {
      (prisma.aiQuota.update as jest.Mock).mockRejectedValue(new Error("DB error"));

      await expect(
        QuotaService.markWarningPosted(BigInt(1))
      ).resolves.toBeUndefined();
    });

    it("can be called multiple times safely", async () => {
      (prisma.aiQuota.update as jest.Mock).mockResolvedValue({});

      await QuotaService.markWarningPosted(BigInt(1));
      await QuotaService.markWarningPosted(BigInt(1));

      expect(prisma.aiQuota.update).toHaveBeenCalledTimes(2);
    });
  });

  describe("hasWarningBeenPosted", () => {
    it("returns true when warning has been posted", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        warningPosted: true,
      });

      const result = await QuotaService.hasWarningBeenPosted(BigInt(1));

      expect(result).toBe(true);
    });

    it("returns false when warning has not been posted", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        warningPosted: false,
      });

      const result = await QuotaService.hasWarningBeenPosted(BigInt(1));

      expect(result).toBe(false);
    });

    it("returns false when quota record is null", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue(null);

      const result = await QuotaService.hasWarningBeenPosted(BigInt(1));

      expect(result).toBe(false);
    });

    it("returns true on DB error (assume posted to avoid spamming)", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const result = await QuotaService.hasWarningBeenPosted(BigInt(1));

      expect(result).toBe(true);
    });

    it("queries with correct installation ID", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        warningPosted: false,
      });

      await QuotaService.hasWarningBeenPosted(BigInt(999));

      expect(prisma.aiQuota.findUnique).toHaveBeenCalledWith({
        where: { installationId: BigInt(999) },
      });
    });
  });

  // =========================================================================
  // Quota Status
  // =========================================================================

  describe("getQuotaStatus", () => {
    it("returns full status for active installation", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        installationId: BigInt(1),
        requestsUsed: 100,
        tokensConsumed: 5000,
        quotaWindowStart: new Date("2026-01-15T00:00:00Z"),
        quotaWindowEnd: new Date("2026-01-16T00:00:00Z"),
        warningPosted: false,
      });

      const status = await QuotaService.getQuotaStatus(BigInt(1));

      expect(status).not.toBeNull();
      expect(status!.requestsUsed).toBe(100);
      expect(status!.maxRequests).toBe(250);
      expect(status!.remainingRequests).toBe(150);
      expect(status!.utilizationPercent).toBe(40);
      expect(status!.isExpired).toBe(false);
      expect(status!.tokensConsumed).toBe(5000);
      expect(status!.warningPosted).toBe(false);
    });

    it("returns expired status when window has passed", async () => {
      const now = new Date("2026-01-16T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        installationId: BigInt(1),
        requestsUsed: 250,
        tokensConsumed: 10000,
        quotaWindowStart: new Date("2026-01-14T00:00:00Z"),
        quotaWindowEnd: new Date("2026-01-15T00:00:00Z"),
        warningPosted: true,
      });

      const status = await QuotaService.getQuotaStatus(BigInt(1));

      expect(status).not.toBeNull();
      expect(status!.isExpired).toBe(true);
      expect(status!.remainingRequests).toBe(250);
      expect(status!.timeUntilResetMs).toBe(0);
    });

    it("returns null for non-existent installation", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue(null);

      const status = await QuotaService.getQuotaStatus(BigInt(999));

      expect(status).toBeNull();
    });

    it("returns null for invalid installation ID", async () => {
      const status = await QuotaService.getQuotaStatus(0n);

      expect(status).toBeNull();
    });

    it("returns null on DB error", async () => {
      (prisma.aiQuota.findUnique as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const status = await QuotaService.getQuotaStatus(BigInt(1));

      expect(status).toBeNull();
    });

    it("calculates timeUntilResetMs correctly", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.findUnique as jest.Mock).mockResolvedValue({
        installationId: BigInt(1),
        requestsUsed: 50,
        tokensConsumed: 1000,
        quotaWindowStart: new Date("2026-01-15T00:00:00Z"),
        quotaWindowEnd: new Date("2026-01-15T18:00:00Z"),
        warningPosted: false,
      });

      const status = await QuotaService.getQuotaStatus(BigInt(1));

      expect(status!.timeUntilResetMs).toBe(6 * 60 * 60 * 1000); // 6 hours
    });
  });

  // =========================================================================
  // Reset Quota
  // =========================================================================

  describe("resetQuota", () => {
    it("resets quota for existing installation", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});

      const result = await QuotaService.resetQuota(BigInt(1));

      expect(result).toBe(true);
      expect(prisma.aiQuota.upsert).toHaveBeenCalledWith({
        where: { installationId: BigInt(1) },
        create: expect.objectContaining({
          installationId: BigInt(1),
          requestsUsed: 0,
          tokensConsumed: 0,
          warningPosted: false,
        }),
        update: expect.objectContaining({
          requestsUsed: 0,
          tokensConsumed: 0,
          warningPosted: false,
        }),
      });
    });

    it("returns false for invalid installation ID", async () => {
      const result = await QuotaService.resetQuota(0n);

      expect(result).toBe(false);
    });

    it("returns false on DB error", async () => {
      (prisma.aiQuota.upsert as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const result = await QuotaService.resetQuota(BigInt(1));

      expect(result).toBe(false);
    });

    it("creates new window start and end times", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.upsert as jest.Mock).mockResolvedValue({});

      await QuotaService.resetQuota(BigInt(1));

      expect(prisma.aiQuota.upsert).toHaveBeenCalledWith(
        expect.objectContaining({
          create: expect.objectContaining({
            quotaWindowStart: now,
            quotaWindowEnd: new Date(now.getTime() + 86400000),
          }),
          update: expect.objectContaining({
            quotaWindowStart: now,
            quotaWindowEnd: new Date(now.getTime() + 86400000),
          }),
        })
      );
    });
  });

  // =========================================================================
  // Bulk Operations
  // =========================================================================

  describe("getBulkQuotaStatus", () => {
    it("returns status map for multiple installations", async () => {
      const now = new Date("2026-01-15T12:00:00Z");
      jest.setSystemTime(now);

      (prisma.aiQuota.findMany as jest.Mock).mockResolvedValue([
        {
          installationId: BigInt(1),
          requestsUsed: 50,
          tokensConsumed: 1000,
          quotaWindowStart: new Date("2026-01-15T00:00:00Z"),
          quotaWindowEnd: new Date("2026-01-16T00:00:00Z"),
          warningPosted: false,
        },
        {
          installationId: BigInt(2),
          requestsUsed: 200,
          tokensConsumed: 8000,
          quotaWindowStart: new Date("2026-01-15T00:00:00Z"),
          quotaWindowEnd: new Date("2026-01-16T00:00:00Z"),
          warningPosted: true,
        },
      ]);

      const result = await QuotaService.getBulkQuotaStatus([BigInt(1), BigInt(2)]);

      expect(result.size).toBe(2);
      expect(result.get(BigInt(1))!.requestsUsed).toBe(50);
      expect(result.get(BigInt(1))!.warningPosted).toBe(false);
      expect(result.get(BigInt(2))!.requestsUsed).toBe(200);
      expect(result.get(BigInt(2))!.warningPosted).toBe(true);
    });

    it("returns null for missing installations", async () => {
      (prisma.aiQuota.findMany as jest.Mock).mockResolvedValue([]);

      const result = await QuotaService.getBulkQuotaStatus([BigInt(1), BigInt(2)]);

      expect(result.size).toBe(2);
      expect(result.get(BigInt(1))).toBeNull();
      expect(result.get(BigInt(2))).toBeNull();
    });

    it("returns empty map for empty input", async () => {
      const result = await QuotaService.getBulkQuotaStatus([]);

      expect(result.size).toBe(0);
      expect(prisma.aiQuota.findMany).not.toHaveBeenCalled();
    });

    it("deduplicates installation IDs", async () => {
      (prisma.aiQuota.findMany as jest.Mock).mockResolvedValue([
        {
          installationId: BigInt(1),
          requestsUsed: 10,
          tokensConsumed: 100,
          quotaWindowStart: new Date(),
          quotaWindowEnd: new Date(Date.now() + 86400000),
          warningPosted: false,
        },
      ]);

      await QuotaService.getBulkQuotaStatus([BigInt(1), BigInt(1), BigInt(1)]);

      expect(prisma.aiQuota.findMany).toHaveBeenCalledWith({
        where: { installationId: { in: [BigInt(1)] } },
      });
    });

    it("returns null entries on DB error", async () => {
      (prisma.aiQuota.findMany as jest.Mock).mockRejectedValue(
        new Error("DB error")
      );

      const result = await QuotaService.getBulkQuotaStatus([BigInt(1)]);

      expect(result.size).toBe(1);
      expect(result.get(BigInt(1))).toBeNull();
    });

    it("calculates utilization for each installation", async () => {
      (prisma.aiQuota.findMany as jest.Mock).mockResolvedValue([
        {
          installationId: BigInt(1),
          requestsUsed: 25,
          tokensConsumed: 500,
          quotaWindowStart: new Date(),
          quotaWindowEnd: new Date(Date.now() + 86400000),
          warningPosted: false,
        },
      ]);

      const result = await QuotaService.getBulkQuotaStatus([BigInt(1)]);
      const status = result.get(BigInt(1))!;

      expect(status.utilizationPercent).toBe(10);
      expect(status.remainingRequests).toBe(225);
    });
  });
});
