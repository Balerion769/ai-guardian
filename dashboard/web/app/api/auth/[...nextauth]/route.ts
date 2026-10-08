import NextAuth from "next-auth";
import { authConfigured, authOptions } from "@/lib/auth";

export const maxDuration = 60;

const handler = NextAuth(authOptions);
export function GET(request: Request, context: unknown) {
  if (!authConfigured()) return new Response("Authentication is not configured", { status: 503 });
  return handler(request, context);
}
export function POST(request: Request, context: unknown) {
  if (!authConfigured()) return new Response("Authentication is not configured", { status: 503 });
  return handler(request, context);
}
