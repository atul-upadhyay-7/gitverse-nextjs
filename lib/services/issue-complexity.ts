import { getGeminiService } from "@/lib/services/geminiService";
import { ComplexityEstimation } from "../../types/issue-triage";
import { buildSafetyPrefix, wrapUntrustedInput } from "@/lib/utils/promptSanitization";

export class IssueComplexityService {
  /**
   * Estimates the complexity and difficulty of an issue based on its content.
   */
  async estimateComplexity(title: string, body: string): Promise<ComplexityEstimation> {
    const prompt = `${buildSafetyPrefix()}

You are an expert senior engineering manager. Analyze the following GitHub issue and estimate its complexity and difficulty for a contributor.

${wrapUntrustedInput("issue_title", title)}
${wrapUntrustedInput("issue_body", body)}

Return ONLY valid JSON matching this schema (no markdown formatting, no code fences):
{
  "complexity": "XS" | "S" | "M" | "L" | "XL",
  "contributorDifficulty": string,
  "beginnerFriendly": boolean,
  "confidence": number
}
`;

    try {
      const gemini = getGeminiService();
      const result = await gemini.chatRaw(prompt);
      
      let rawJson = result.text;
      rawJson = rawJson.replace(/```json/gi, "").replace(/```/g, "").trim();
      
      const parsed = JSON.parse(rawJson) as ComplexityEstimation;
      
      return {
        complexity: parsed.complexity || "M",
        contributorDifficulty: parsed.contributorDifficulty || "Unknown",
        beginnerFriendly: Boolean(parsed.beginnerFriendly),
        confidence: typeof parsed.confidence === "number" ? parsed.confidence : 50,
      };
    } catch (error) {
      console.error("[IssueComplexityService] Error estimating complexity:", error);
      return {
        complexity: "M",
        contributorDifficulty: "Unknown",
        beginnerFriendly: false,
        confidence: 0,
      };
    }
  }
}
