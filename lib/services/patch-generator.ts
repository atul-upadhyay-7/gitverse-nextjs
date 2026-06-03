import { getGeminiService } from "@/lib/services/geminiService";
import { PRReviewIssue } from "@/lib/services/prReviewService";
import { SelfHealingPatch } from "../../types/self-healing";
import { buildSafetyPrefix, wrapUntrustedInput } from "@/lib/utils/promptSanitization";

export class PatchGeneratorService {
  /**
   * Instructs the LLM to generate a safe code replacement for the given issue.
   */
  async generatePatch(
    issue: PRReviewIssue,
    fileContent: string,
  ): Promise<Partial<SelfHealingPatch> | null> {
    if (!issue.file || !issue.line) return null;

    const gemini = getGeminiService();

    const prompt = `${buildSafetyPrefix()}

You are an expert software engineer and security researcher.
An automated code review has detected a high/critical issue in a pull request.
Your task is to generate a fix for this issue that can be applied cleanly to the code.

${wrapUntrustedInput("issue_file", issue.file || "N/A")}
${wrapUntrustedInput("issue_title", issue.title)}
${wrapUntrustedInput("issue_category", issue.category)}
${wrapUntrustedInput("issue_explanation", issue.explanation)}
${wrapUntrustedInput("issue_suggestion", issue.suggestion)}

Here is the current content of the file:
\`\`\`
${wrapUntrustedInput("file_content", fileContent)}
\`\`\`

Generate a precise code replacement for the issue. You must specify the exact startLine and endLine of the replacement block, and provide the exact new code that should replace it.
If the fix spans multiple distinct locations or files, you MUST set "isValid" to false. We only support single contiguous block replacements for now.

Return ONLY valid JSON matching this schema (no markdown, no extra text):
{
  "isValid": boolean,
  "startLine": number,
  "endLine": number,
  "suggestionBody": string,
  "explanation": string,
  "confidenceScore": number
}
`;

    try {
      const response = await gemini.chatRaw(prompt);
      
      const rawText = response.text.trim();
      let jsonText = rawText;
      if (rawText.startsWith("```json")) {
        jsonText = rawText.replace(/^```json/, "").replace(/```$/, "").trim();
      } else if (rawText.startsWith("```")) {
        jsonText = rawText.replace(/^```/, "").replace(/```$/, "").trim();
      }

      const parsed = JSON.parse(jsonText);
      
      if (!parsed.isValid) return null;

      return {
        issue,
        file: issue.file,
        startLine: parsed.startLine,
        endLine: parsed.endLine || issue.line,
        suggestionBody: parsed.suggestionBody || "",
        explanation: parsed.explanation || "",
        confidenceScore: typeof parsed.confidenceScore === 'number' ? parsed.confidenceScore : 50,
      };
    } catch (error) {
      console.error("[PatchGenerator] Failed to generate patch:", error);
      return null;
    }
  }
}
