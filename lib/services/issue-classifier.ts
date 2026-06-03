import { getGeminiService } from "@/lib/services/geminiService";
import { IssueClassification } from "../../types/issue-triage";
import { buildSafetyPrefix, wrapUntrustedInput } from "@/lib/utils/promptSanitization";

export class IssueClassifierService {
  /**
   * Analyzes an issue's title and body to classify it into a category and extract tags.
   */
  async classifyIssue(title: string, body: string): Promise<IssueClassification> {
    const prompt = `${buildSafetyPrefix()}

You are an expert technical product manager. Analyze the following GitHub issue and classify it.

${wrapUntrustedInput("issue_title", title)}
${wrapUntrustedInput("issue_body", body)}

Return ONLY valid JSON matching this schema (no markdown formatting, no code fences):
{
  "category": "bug" | "enhancement" | "documentation" | "refactor" | "performance" | "security" | "ui/ux" | "testing" | "question" | "unknown",
  "tags": string[],
  "confidence": number
}
`;

    try {
      const gemini = getGeminiService();
      const result = await gemini.chatRaw(prompt);
      
      let rawJson = result.text;
      // Clean markdown formatting if any
      rawJson = rawJson.replace(/```json/gi, "").replace(/```/g, "").trim();
      
      const parsed = JSON.parse(rawJson) as IssueClassification;
      
      return {
        category: parsed.category || "unknown",
        tags: Array.isArray(parsed.tags) ? parsed.tags : [],
        confidence: typeof parsed.confidence === "number" ? parsed.confidence : 50,
      };
    } catch (error) {
      console.error("[IssueClassifierService] Error classifying issue:", error);
      return {
        category: "unknown",
        tags: [],
        confidence: 0,
      };
    }
  }
}
