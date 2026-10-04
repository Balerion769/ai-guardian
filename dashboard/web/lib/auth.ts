import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from "next-auth/providers/github";
import { demoEnabled } from "@/lib/proxy";

const githubId = process.env.GITHUB_ID ?? process.env.GITHUB_CLIENT_ID;
const githubSecret = process.env.GITHUB_SECRET ?? process.env.GITHUB_CLIENT_SECRET;
const hasGithub = Boolean(githubId && githubSecret);
export const isDemoMode = demoEnabled(process.env.NODE_ENV, hasGithub);
if (process.env.NODE_ENV !== "production" && !process.env.NEXTAUTH_URL) {
  process.env.NEXTAUTH_URL = "http://localhost:3000";
}

export function authConfigured(): boolean {
  return process.env.NODE_ENV !== "production" || Boolean(process.env.NEXTAUTH_SECRET);
}

const providers: NextAuthOptions["providers"] = hasGithub
  ? [
      GitHubProvider({
        clientId: githubId!,
        clientSecret: githubSecret!,
        authorization: { params: { scope: "read:user user:email read:org repo" } },
      }),
    ]
  : isDemoMode
    ? [
        CredentialsProvider({
          id: "demo",
          name: "Local demo",
          credentials: {},
          async authorize() {
            return {
              id: "demo-user",
              name: "Demo Developer",
              email: "demo@local.invalid",
              orgId: "demo-org",
              demo: true,
            };
          },
        }),
      ]
    : [];

async function exchangeGithubToken(
  accessToken: string,
): Promise<{ cookie: string; orgId: string }> {
  const response = await fetch(
    `${process.env.BACKEND_API_URL ?? "http://127.0.0.1:8001"}/api/v1/auth/github`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}` },
      cache: "no-store",
    },
  );
  if (!response.ok) throw new Error("Backend GitHub sign-in failed");
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0];
  const body: { org_id?: string } = await response.json();
  if (!cookie?.startsWith("session=") || !body.org_id)
    throw new Error("Backend session unavailable");
  return { cookie, orgId: body.org_id };
}

export const authOptions: NextAuthOptions = {
  providers,
  secret: process.env.NEXTAUTH_SECRET ?? "local-demo-secret-for-development-only-change-me",
  session: { strategy: "jwt", maxAge: 8 * 60 * 60 },
  pages: { signIn: "/login", error: "/login" },
  callbacks: {
    async signIn({ user, account }) {
      if (account?.provider === "demo") return isDemoMode;
      if (account?.provider !== "github" || !account.access_token) return false;
      try {
        const backend = await exchangeGithubToken(account.access_token);
        user.backendCookie = backend.cookie;
        user.orgId = backend.orgId;
        return true;
      } catch {
        return false;
      }
    },
    async jwt({ token, user, trigger, session }) {
      if (user) {
        token.orgId = user.orgId;
        token.backendCookie = user.backendCookie;
        token.demo = user.demo;
      }
      if (
        trigger === "update" &&
        typeof session?.orgId === "string" &&
        token.backendCookie &&
        session.orgId !== token.orgId
      ) {
        try {
          const response = await fetch(
            `${process.env.BACKEND_API_URL ?? "http://127.0.0.1:8001"}/api/v1/orgs/${encodeURIComponent(session.orgId)}`,
            {
              headers: { Cookie: token.backendCookie },
              cache: "no-store",
            },
          );
          if (response.ok) token.orgId = session.orgId;
        } catch {
          /* Keep the current organization if verification is unavailable. */
        }
      }
      return token;
    },
    async session({ session, token }) {
      session.orgId = token.orgId ?? "";
      session.demo = Boolean(token.demo);
      return session;
    },
  },
};
