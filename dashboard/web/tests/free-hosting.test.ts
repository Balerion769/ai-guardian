import { afterEach, describe, expect, it, vi } from "vitest";
import { getOrgs } from "@/lib/api";

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); vi.useRealTimers(); });

describe("free hosting client", () => {
  it("keeps browser requests on the authenticated relative proxy even with a public API URL", async () => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "https://example.onrender.com");
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => Response.json([]));
    vi.stubGlobal("fetch", fetchMock);
    await expect(getOrgs()).resolves.toEqual([]);
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/api/dashboard/orgs");
  });

  it("cancels a stalled request after ten seconds and tells the user to retry", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("fetch", (_input: RequestInfo | URL, init: RequestInit) => new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")));
    }));
    const result = expect(getOrgs()).rejects.toMatchObject({ status: 504, message: expect.stringContaining("sleeping") });
    await vi.advanceTimersByTimeAsync(10_000);
    await result;
  });
});
