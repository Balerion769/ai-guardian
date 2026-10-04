import type { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    orgId: string;
    demo: boolean;
    user: DefaultSession["user"];
  }
  interface User {
    backendCookie?: string;
    orgId?: string;
    demo?: boolean;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    backendCookie?: string;
    orgId?: string;
    demo?: boolean;
  }
}
