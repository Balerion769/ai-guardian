import { afterEach, describe, expect, it, vi } from "vitest";
import type { Account, Session, User } from "next-auth";
import type { AdapterUser } from "next-auth/adapters";
import type { JWT } from "next-auth/jwt";
import { authOptions } from "@/lib/auth";

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("NextAuth backend exchange", () => {
  it("keeps the backend cookie in the encrypted JWT rather than the browser session", async () => {
    const fetchMock = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ org_id: "org-123" }), {
          status: 200,
          headers: { "Set-Cookie": "session=signed-value; Path=/; HttpOnly" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const user: User = { id: "user-1", name: "Dev" };
    const accepted = await authOptions.callbacks!.signIn!({
      user,
      account: { provider: "github", access_token: "provider-token" } as Account,
      profile: undefined,
      email: undefined,
      credentials: undefined,
    });
    expect(accepted).toBe(true);
    expect((fetchMock.mock.calls[0][1]?.headers as Record<string, string>).Authorization).toBe(
      "Bearer provider-token",
    );
    const token = await authOptions.callbacks!.jwt!({
      token: { sub: "user-1" } as JWT,
      user,
      account: null,
      profile: undefined,
      trigger: "signIn",
      isNewUser: false,
    });
    expect(token.backendCookie).toBe("session=signed-value");
    const session = (await authOptions.callbacks!.session!({
      session: { expires: "later", user: { name: "Dev" } } as Session,
      token,
      user: { ...user, emailVerified: null } as AdapterUser,
      trigger: "update",
      newSession: {},
    })) as Session;
    expect(session.orgId).toBe("org-123");
    expect(JSON.stringify(session)).not.toContain("signed-value");
  });

  it("denies sign-in when the hosted API rejects the token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("Unauthorized", { status: 401 })),
    );
    const accepted = await authOptions.callbacks!.signIn!({
      user: { id: "user-1" },
      account: { provider: "github", access_token: "bad" } as Account,
      profile: undefined,
      email: undefined,
      credentials: undefined,
    });
    expect(accepted).toBe(false);
  });

  it.each([503, 500, 429])("reports backend HTTP %s as unavailable, not an account denial", async (status) => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("Unavailable", { status })));
    const accepted = await authOptions.callbacks!.signIn!({
      user: { id: "another-github-account" },
      account: { provider: "github", access_token: "verified-token" } as Account,
      profile: undefined, email: undefined, credentials: undefined,
    });
    expect(accepted).toBe("/login?error=BackendUnavailable");
  });

  it("reports a network timeout without implying the GitHub account is forbidden", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new DOMException("Timeout", "AbortError"); }));
    const accepted = await authOptions.callbacks!.signIn!({
      user: { id: "user-2" },
      account: { provider: "github", access_token: "verified-token" } as Account,
      profile: undefined, email: undefined, credentials: undefined,
    });
    expect(accepted).toBe("/login?error=BackendUnavailable");
  });

  it("allows a cold backend exchange to take longer than ten seconds", async () => {
    vi.useFakeTimers();
    let complete!: (response: Response) => void;
    let signal: AbortSignal | null | undefined;
    vi.stubGlobal("fetch", vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init?.signal;
      return new Promise<Response>((resolve) => { complete = resolve; });
    }));
    const pending = authOptions.callbacks!.signIn!({
      user: { id: "new-public-github-account" },
      account: { provider: "github", access_token: "verified-token" } as Account,
      profile: undefined, email: undefined, credentials: undefined,
    });
    await vi.advanceTimersByTimeAsync(20_000);
    expect(signal?.aborted).toBe(false);
    complete(new Response(JSON.stringify({ org_id: "new-private-workspace" }), {
      status: 200, headers: { "Set-Cookie": "session=test-signature; HttpOnly" },
    }));
    expect(await pending).toBe(true);
  });
});
