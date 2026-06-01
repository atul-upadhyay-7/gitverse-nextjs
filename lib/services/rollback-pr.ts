import { githubService } from "./githubService";
import { getRevertGeneratorService } from "./revert-generator";
import { getIncidentReportService } from "./incident-report";
import {
  IncidentPayload,
  IncidentCorrelation,
  RollbackResult,
} from "@/types/incident-response";

const GITHUB_OWNER_REGEX = /^[a-zA-Z0-9._-]+$/;
const GITHUB_REPO_REGEX = /^[a-zA-Z0-9._-]+$/;

export class RollbackPrService {
  /**
   * Validates owner/repo strings to prevent injection into GitHub API paths.
   */
  private validateGitHubPath(owner: string, repo: string): string | null {
    if (!owner || !GITHUB_OWNER_REGEX.test(owner)) {
      return "Invalid owner format";
    }
    if (!repo || !GITHUB_REPO_REGEX.test(repo)) {
      return "Invalid repo format";
    }
    if (owner.length > 100 || repo.length > 100) {
      return "Owner or repo name too long";
    }
    return null;
  }

  /**
   * Fetches the default branch for a repository.
   * This avoids hardcoding "main" which may be incorrect.
   */
  private async getDefaultBranch(
    client: any,
    owner: string,
    repo: string
  ): Promise<string> {
    try {
      const { data: repoData } = await client.get(
        `/repos/${owner}/${repo}`
      );
      return repoData.default_branch || "main";
    } catch (error) {
      console.error(
        `[RollbackPr] Failed to fetch default branch for ${owner}/${repo}, using "main":`,
        error
      );
      return "main";
    }
  }

  /**
   * Orchestrates the creation of an emergency rollback PR.
   */
  public async executeRollback(
    installationId: number,
    owner: string,
    repo: string,
    incident: IncidentPayload,
    correlation: IncidentCorrelation
  ): Promise<RollbackResult> {
    console.log(
      `[RollbackPr] Starting rollback for PR #${correlation.likelyPrNumber}`
    );

    // Validate inputs
    const pathError = this.validateGitHubPath(owner, repo);
    if (pathError) {
      return { success: false, error: pathError };
    }

    if (!correlation.likelyPrNumber) {
      return {
        success: false,
        error: "No likely PR identified to rollback.",
      };
    }

    const MIN_ROLLBACK_CONFIDENCE = parseInt(
      process.env.MIN_ROLLBACK_CONFIDENCE || "85",
      10
    );

    if (
      correlation.confidenceScore < MIN_ROLLBACK_CONFIDENCE
    ) {
      return {
        success: false,
        error: `Confidence score (${correlation.confidenceScore}) is below threshold (${MIN_ROLLBACK_CONFIDENCE}). Human review required.`,
      };
    }

    if (!correlation.likelyCommitSha) {
      return {
        success: false,
        error: "No commit SHA identified for rollback.",
      };
    }

    try {
      const client = (githubService as any).client;

      // Fetch the actual default branch instead of hardcoding "main"
      const baseBranch = await this.getDefaultBranch(client, owner, repo);

      // 1. Generate Revert Branch
      const revertGenerator = getRevertGeneratorService();
      const revertBranchName =
        await revertGenerator.createRevertBranch(
          installationId,
          owner,
          repo,
          correlation.likelyCommitSha,
          incident.id
        );

      // 2. Generate Incident Report for PR Body
      const reportService = getIncidentReportService();
      const prBody = reportService.generatePrDescription(
        incident,
        correlation
      );

      // 3. Create Emergency PR targeting the correct default branch
      const { data: pr } = await client.post(
        `/repos/${owner}/${repo}/pulls`,
        {
          title: `🚨 Emergency Rollback: Revert PR #${correlation.likelyPrNumber} after production incident`,
          head: revertBranchName,
          base: baseBranch,
          body: prBody,
        }
      );

      console.log(
        `[RollbackPr] Created emergency rollback PR: ${pr.html_url}`
      );

      // 4. Auto-merge logic
      const AUTO_ROLLBACK_ENABLED =
        process.env.AUTO_ROLLBACK_ENABLED === "true";
      let autoMerged = false;

      if (AUTO_ROLLBACK_ENABLED) {
        try {
          await client.put(
            `/repos/${owner}/${repo}/pulls/${pr.number}/merge`,
            {
              commit_title: `Auto-merge: Emergency Rollback of PR #${correlation.likelyPrNumber}`,
              merge_method: "squash",
            }
          );
          autoMerged = true;
          console.log(
            `[RollbackPr] Auto-merged emergency rollback PR #${pr.number}`
          );
        } catch (mergeError) {
          console.error(
            `[RollbackPr] Auto-merge failed for PR #${pr.number}:`,
            mergeError
          );
        }
      }

      return {
        success: true,
        branchName: revertBranchName,
        prUrl: pr.html_url,
        prNumber: pr.number,
        autoMerged,
      };
    } catch (error: any) {
      console.error("[RollbackPr] Failed to execute rollback:", error);
      return {
        success: false,
        error:
          error.message || "Unknown error occurred during rollback",
      };
    }
  }
}

let rollbackPrSingleton: RollbackPrService | null = null;

export function getRollbackPrService(): RollbackPrService {
  if (!rollbackPrSingleton) {
    rollbackPrSingleton = new RollbackPrService();
  }
  return rollbackPrSingleton;
}
