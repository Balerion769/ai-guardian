import { backendUrl, fetchWithTimeout } from "@/lib/http";

export const maxDuration = 60;
export const dynamic = "force-dynamic";

/** Wake the free backend before starting OAuth; never exchange credentials here. */
export async function GET(): Promise<Response> {
  try {
    const response = await fetchWithTimeout(`${backendUrl()}/health`, { cache: "no-store" }, 55_000);
    if (!response.ok || (await response.json()).status !== "ok") throw new Error("Backend unavailable");
    return Response.json({ status: "ready" }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return Response.json({ status: "unavailable" }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
