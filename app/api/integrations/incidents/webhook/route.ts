import { NextRequest, NextResponse } from "next/server";
import { getIncidentIngestionService } from "@/lib/services/incident-ingestion";
import { getDeploymentAnalysisService } from "@/lib/services/deployment-analysis";
import { getIncidentCorrelationService } from "@/lib/services/incident-correlation";
import { getRollbackPrService } from "@/lib/services/rollback-pr";
import { IncidentReport } from "@/types/incident-response";
import { verifyGitHubWebhookSignature } from "@/lib/utils/githubWebhook";
import { QuotaService } from "@/lib/services/quotaService";
import { getClientIp } from "@/lib/services/rateLimitService";

const MAX_PAYLOAD_SIZE_BYTES = 1024 * 1024; // 1MB
const VALID_SOURCES = ["sentry", "datadog", "pagerduty", "generic"] as const;
type ValidSource = (typeof VALID_SOURCES)[number];

const GITHUB_OWNER_REGEX = /^[a-zA-Z0-9._-]+$/;
const GITHUB_REPO_REGEX = /^[a-zA-Z0-9._-]+$/;
const MAX_INSTALLATION_ID = 999_999_999;
const MAX_QUERY_PARAM_LENGTH = 255;

function validateOwner(owner: string): string | null {
  if (!owner || typeof owner !== "string") return "Owner is required";
  if (owner.length > MAX_QUERY_PARAM_LENGTH) return "Owner name too long";
  if (!GITHUB_OWNER_REGEX.test(owner)) return "Owner contains invalid characters";
  return null;
}

function validateRepo(repo: string): string | null {
  if (!repo || typeof repo !== "string") return "Repo is required";
  if (repo.length > MAX_QUERY_PARAM_LENGTH) return "Repo name too long";
  if (!GITHUB_REPO_REGEX.test(repo)) return "Repo contains invalid characters";
  return null;
}

function validateInstallationId(raw: string | null): { value: number; error: string | null } {
  if (!raw) return { value: 1, error: null }; // Default to 1

  const parsed = parseInt(raw, 10);
  if (isNaN(parsed)) return { value: 0, error: "installationId must be a number" };
  if (parsed <= 0) return { value: 0, error: "installationId must be positive" };
  if (parsed > MAX_INSTALLATION_ID) return { value: 0, error: "installationId too large" };

  return { value: parsed, error: null };
}

function validateSource(source: string | null): ValidSource {
  if (source && VALID_SOURCES.includes(source as ValidSource)) {
    return source as ValidSource;
  }
  return "generic";
}

function validateSeverity(severity: string | undefined): "critical" | "high" | "medium" | "low" {
  if (!severity) return "medium";
  const lower = severity.toLowerCase();
  if (["fatal", "critical", "p1", "high"].includes(lower)) return "critical";
  if (["error", "p2"].includes(lower)) return "high";
  if (["warning", "p3", "medium"].includes(lower)) return "medium";
  return "low";
}

function validateIncidentPayload(payload: any): { valid: boolean; error?: string } {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return { valid: false, error: "Payload must be a JSON object" };
  }

  if (payload.id !== undefined && typeof payload.id !== "string" && typeof payload.id !== "number") {
    return { valid: false, error: "Incident id must be a string or number" };
  }

  if (payload.title !== undefined && typeof payload.title !== "string") {
    return { valid: false, error: "Incident title must be a string" };
  }

  if (payload.severity !== undefined && typeof payload.severity !== "string") {
    return { valid: false, error: "Incident severity must be a string" };
  }

  if (payload.timestamp !== undefined && typeof payload.timestamp !== "string") {
    return { valid: false, error: "Incident timestamp must be a string" };
  }

  if (payload.timestamp) {
    const ts = new Date(payload.timestamp);
    if (isNaN(ts.getTime())) {
      return { valid: false, error: "Incident timestamp is not a valid date" };
    }
    // Reject timestamps more than 24 hours in the future
    if (ts.getTime() > Date.now() + 24 * 60 * 60 * 1000) {
      return { valid: false, error: "Incident timestamp is too far in the future" };
    }
    // Reject timestamps more than 7 days in the past
    if (ts.getTime() < Date.now() - 7 * 24 * 60 * 60 * 1000) {
      return { valid: false, error: "Incident timestamp is too far in the past" };
    }
  }

  return { valid: true };
}

export async function POST(req: NextRequest) {
  try {
    // 1. IP-based rate limiting (20 requests per minute per IP)
    const clientIp = getClientIp(req);
    const isIpAllowed = await QuotaService.checkWebhookRateLimit(
      `incident_webhook_ip_${clientIp}`,
      20,
      60000
    );
    if (!isIpAllowed) {
      return NextResponse.json(
        { success: false, error: "Too many requests" },
        { status: 429 }
      );
    }

    // 2. Read and validate payload size
    const rawBody = await req.text();
    if (rawBody.length > MAX_PAYLOAD_SIZE_BYTES) {
      return NextResponse.json(
        { success: false, error: "Payload too large" },
        { status: 413 }
      );
    }

    if (rawBody.length === 0) {
      return NextResponse.json(
        { success: false, error: "Empty payload" },
        { status: 400 }
      );
    }

    // 3. Verify webhook signature (if secret is configured)
    const webhookSecret = process.env.INCIDENT_WEBHOOK_SECRET;
    if (webhookSecret) {
      const signature = req.headers.get("x-hub-signature-256") ||
                        req.headers.get("x-webhook-signature");

      if (!signature) {
        return NextResponse.json(
          { success: false, error: "Missing webhook signature" },
          { status: 401 }
        );
      }

      const isValid = verifyGitHubWebhookSignature({
        rawBody,
        signature256Header: signature,
        webhookSecret,
      });

      if (!isValid) {
        console.error("[IncidentWebhook] Invalid webhook signature");
        return NextResponse.json(
          { success: false, error: "Invalid webhook signature" },
          { status: 401 }
        );
      }
    } else {
      console.warn(
        "[IncidentWebhook] INCIDENT_WEBHOOK_SECRET not configured — " +
        "skipping signature verification (INSECURE in production)"
      );
    }

    // 4. Parse JSON payload
    let payload: any;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return NextResponse.json(
        { success: false, error: "Invalid JSON payload" },
        { status: 400 }
      );
    }

    // 5. Validate incident payload structure
    const payloadValidation = validateIncidentPayload(payload);
    if (!payloadValidation.valid) {
      return NextResponse.json(
        { success: false, error: payloadValidation.error },
        { status: 400 }
      );
    }

    // 6. Parse and validate source header
    const sourceHeader = req.headers.get("x-incident-source") || "generic";
    const source = validateSource(sourceHeader);

    // 7. Parse and validate query parameters
    const url = new URL(req.url);
    const installationIdResult = validateInstallationId(
      url.searchParams.get("installationId")
    );
    if (installationIdResult.error) {
      return NextResponse.json(
        { success: false, error: installationIdResult.error },
        { status: 400 }
      );
    }
    const installationId = installationIdResult.value;

    const ownerRaw = url.searchParams.get("owner") || "";
    const ownerError = validateOwner(ownerRaw);
    if (ownerError) {
      return NextResponse.json(
        { success: false, error: ownerError },
        { status: 400 }
      );
    }
    const owner = ownerRaw;

    const repoRaw = url.searchParams.get("repo") || "";
    const repoError = validateRepo(repoRaw);
    if (repoError) {
      return NextResponse.json(
        { success: false, error: repoError },
        { status: 400 }
      );
    }
    const repo = repoRaw;

    console.log(
      `[IncidentWebhook] Received incident webhook from ${source} ` +
      `for ${owner}/${repo} (installation: ${installationId})`
    );

    // 8. Ingest and normalize the incident
    const ingestionService = getIncidentIngestionService();
    const incident = ingestionService.processWebhook(source, payload);

    // 9. Fetch deployment context
    const deploymentService = getDeploymentAnalysisService();
    const context = await deploymentService.getRecentDeploymentContext(
      installationId,
      owner,
      repo,
      incident.timestamp
    );

    // 10. Correlate with recent code changes
    const correlationService = getIncidentCorrelationService();
    const correlation = await correlationService.correlateIncident(
      incident,
      context
    );

    let rollbackResult = null;
    const report: Partial<IncidentReport> = {
      incidentId: incident.id,
      summary: incident.title,
      severity: incident.severity,
      likelyPrNumber: correlation.likelyPrNumber,
      confidenceScore: correlation.confidenceScore,
      affectedFiles: correlation.impactedFiles,
      rollbackPrepared: false,
      autoMerged: false,
      createdAt: new Date().toISOString(),
    };

    // 11. Trigger rollback if correlation is strong enough
    if (correlation.likelyPrNumber) {
      const rollbackService = getRollbackPrService();
      rollbackResult = await rollbackService.executeRollback(
        installationId,
        owner,
        repo,
        incident,
        correlation
      );

      if (rollbackResult.success) {
        report.rollbackPrepared = true;
        report.emergencyPrUrl = rollbackResult.prUrl;
        report.autoMerged = rollbackResult.autoMerged || false;
      } else {
        console.warn(
          `[IncidentWebhook] Rollback skipped or failed: ${rollbackResult.error}`
        );
      }
    } else {
      console.warn("[IncidentWebhook] No likely PR identified for incident.");
    }

    return NextResponse.json(
      { success: true, report, error: rollbackResult?.error },
      { status: 200 }
    );
  } catch (error: any) {
    console.error("[IncidentWebhook] Error processing webhook:", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 }
    );
  }
}
