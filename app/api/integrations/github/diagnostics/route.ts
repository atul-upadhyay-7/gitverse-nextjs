import { NextRequest, NextResponse } from "next/server";
import { requireAuth } from "@/lib/middleware";
import { GitHubAppService } from "@/lib/services/githubAppService";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  try {
    await requireAuth(request);

    const diagnostics: Record<string, any> = {
      appConfigured: !!process.env.GITHUB_APP_ID && !!process.env.GITHUB_APP_PRIVATE_KEY,
      hasInstallations: false,
      apiReachable: false,
    };

    if (diagnostics.appConfigured) {
      try {
        const app = new GitHubAppService();
        const jwt = app.getJwt();
        diagnostics.jwtIssued = !!jwt;
        diagnostics.apiReachable = true;
      } catch (err: any) {
        diagnostics.appError = err.message;
      }
    }

    return NextResponse.json({ diagnostics });
  } catch (error: any) {
    return NextResponse.json(
      { error: "Diagnostics check failed" },
      { status: 500 }
    );
  }
}
