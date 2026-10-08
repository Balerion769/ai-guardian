import { afterEach, describe, expect, it, vi } from "vitest";
import { GET } from "@/app/api/auth/backend-ready/route";
afterEach(() => vi.unstubAllGlobals());
describe("Sign-in backend readiness", () => {
  it("reports ready only after the backend health check succeeds", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response('{"status":"ok"}')));
    const response = await GET();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ status: "ready" });
    expect(response.headers.get("Cache-Control")).toBe("no-store");
  });
  it.each([new Response("Starting", { status: 503 }), new Response("not-json")])("fails closed when health is unavailable or invalid", async (upstream) => {
    vi.stubGlobal("fetch", vi.fn(async () => upstream));
    expect((await GET()).status).toBe(503);
  });
});
