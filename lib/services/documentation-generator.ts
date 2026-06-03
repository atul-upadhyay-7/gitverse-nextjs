import { getGeminiService } from "@/lib/services/geminiService";
import { DocumentationPatch, DriftAnalysisResult } from "../../types/documentation-drift";
import { buildSafetyPrefix, wrapUntrustedInput } from "@/lib/utils/promptSanitization";

export class DocumentationGeneratorService {
  /**
   * Generates a patched version of the file with updated documentation.
   */
  async generatePatch(filePath: string, content: string, drift: DriftAnalysisResult): Promise<DocumentationPatch> {
    const gemini = getGeminiService();

    const prompt = `${buildSafetyPrefix()}

You are an expert technical writer and code reviewer.
The following source code has documentation drift. Your job is to output the ENTIRE file content with the documentation (JSDoc, inline comments, etc.) FIXED to match the current implementation.

Important Rules:
1. ONLY modify documentation (comments, JSDoc, docstrings).
2. DO NOT change ANY functional code (no changing of variable names, logic, syntax, formatting outside comments).
3. Preserve the exact file structure, imports, and exports.
4. Output the full modified file content.
5. Provide a JSON response containing the suggestedContent (the full file), confidence, reasoning, and summary of changes.

${wrapUntrustedInput("file_path", filePath)}

Detected Drift Issues:
${wrapUntrustedInput("drift_outdated_descriptions", drift.outdatedDescriptions.join(', '))}
${wrapUntrustedInput("drift_missing_parameters", drift.missingParameters.join(', '))}
${wrapUntrustedInput("drift_removed_parameters", drift.removedParameters.join(', '))}
${wrapUntrustedInput("drift_incorrect_return_values", drift.incorrectReturnValues.join(', '))}
${wrapUntrustedInput("drift_stale_examples", drift.staleExamples.join(', '))}

Source Code:
\`\`\`
${wrapUntrustedInput("source_code", content)}
\`\`\`

Return a JSON object matching this schema exactly (no markdown formatting, no comments, just valid JSON):
{
  "suggestedContent": string,
  "suggestedFixConfidence": number,
  "reasoning": string,
  "summaryOfChanges": string
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
      
      return {
        originalContent: content,
        suggestedContent: parsed.suggestedContent || content,
        suggestedFixConfidence: typeof parsed.suggestedFixConfidence === 'number' ? parsed.suggestedFixConfidence : 0,
        reasoning: parsed.reasoning || "No reasoning provided.",
        summaryOfChanges: parsed.summaryOfChanges || "Fixed documentation drift."
      };
    } catch (error) {
      console.error("[DocumentationGenerator] Failed to generate patch:", error);
      return {
        originalContent: content,
        suggestedContent: content,
        suggestedFixConfidence: 0,
        reasoning: "Failed to generate patch.",
        summaryOfChanges: ""
      };
    }
  }
}
