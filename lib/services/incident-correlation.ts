import { getGeminiService } from "./geminiService";
import { IncidentPayload, IncidentCorrelation } from "@/types/incident-response";
import { buildSafetyPrefix, wrapUntrustedInput } from "@/lib/utils/promptSanitization";

export class IncidentCorrelationService {
  /**
   * Correlates an incoming incident with recent code changes using Gemini.
   */
  public async correlateIncident(
    incident: IncidentPayload,
    repositoryContext: string
  ): Promise<IncidentCorrelation> {
    console.log(`[IncidentCorrelation] Starting correlation for incident: ${incident.title}`);

    const prompt = `${buildSafetyPrefix()}

You are a site reliability engineer and an expert code analyst.
An incident has occurred in production. Please analyze the incident details and the recent repository context to identify the most likely root cause.

Incident Details:
${wrapUntrustedInput("incident_title", incident.title)}
${wrapUntrustedInput("incident_severity", incident.severity)}
${wrapUntrustedInput("incident_service", incident.affectedService || "Unknown")}
${wrapUntrustedInput("incident_timestamp", incident.timestamp)}
${wrapUntrustedInput("incident_environment", incident.environment)}

Stack Trace / Error Details:
${wrapUntrustedInput("stack_trace", incident.stackTrace || "None provided")}

Repository Context (Recent PRs, Commits, Deployments):
${wrapUntrustedInput("repository_context", repositoryContext)}

Based on this information, extract the following in JSON format:
{
  "likelyPrNumber": number,
  "likelyCommitSha": string,
  "impactedFiles": string[],
  "impactedServices": string[],
  "confidenceScore": number,
  "analysisDetails": string
}

Provide ONLY the valid JSON object and nothing else.
`;

    const geminiService = getGeminiService();
    try {
      const response = await geminiService.chatRaw(prompt);
      
      // Attempt to parse JSON response. Gemini might wrap it in ```json
      let responseText = response.text.trim();
      if (responseText.startsWith("\`\`\`json")) {
        responseText = responseText.replace(/^\`\`\`json/, "").replace(/\`\`\`$/, "").trim();
      } else if (responseText.startsWith("\`\`\`")) {
        responseText = responseText.replace(/^\`\`\`/, "").replace(/\`\`\`$/, "").trim();
      }

      const parsed = JSON.parse(responseText);

      return {
        likelyPrNumber: parsed.likelyPrNumber,
        likelyCommitSha: parsed.likelyCommitSha,
        impactedFiles: parsed.impactedFiles || [],
        impactedServices: parsed.impactedServices || [],
        confidenceScore: parsed.confidenceScore || 0,
        analysisDetails: parsed.analysisDetails || "No detailed analysis provided.",
      };
    } catch (error) {
      console.error("[IncidentCorrelation] Failed to correlate incident:", error);
      return {
        impactedFiles: [],
        impactedServices: [],
        confidenceScore: 0,
        analysisDetails: "Correlation failed due to an error.",
      };
    }
  }
}

let correlationServiceSingleton: IncidentCorrelationService | null = null;

export function getIncidentCorrelationService(): IncidentCorrelationService {
  if (!correlationServiceSingleton) {
    correlationServiceSingleton = new IncidentCorrelationService();
  }
  return correlationServiceSingleton;
}
