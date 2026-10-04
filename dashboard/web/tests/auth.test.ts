import { afterEach, describe, expect, it, vi } from "vitest";
import type { Account, Session, User } from "next-auth";
import type { AdapterUser } from "next-auth/adapters";
import type { JWT } from "next-auth/jwt";
import { authOptions } from "@/lib/auth";

afterEach(() => vi.unstubAllGlobals());

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
});
