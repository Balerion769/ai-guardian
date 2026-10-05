import { getToken } from "next-auth/jwt";
import { type NextRequest } from "next/server";
import { demoResponse } from "@/lib/demo";
import { isAllowedMutationOrigin, isAllowedProxyPath } from "@/lib/proxy";
import { authConfigured } from "@/lib/auth";

export const dynamic = "force-dynamic";

async function forward(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> },
): Promise<Response> {
  if (!authConfigured())
    return Response.json({ detail: "Authentication is not configured" }, { status: 503 });
  const token = await getToken({
    req: request,
    secret: process.env.NEXTAUTH_SECRET ?? "local-demo-secret-for-development-only-change-me",
  });
  if (!token?.orgId) return Response.json({ detail: "Sign in required" }, { status: 401 });
  const path = (await params).path;
  if (!isAllowedProxyPath(path, token.orgId, request.method))
    return Response.json({ detail: "Resource unavailable" }, { status: 404 });
  if (
    !["GET", "HEAD"].includes(request.method) &&
    !isAllowedMutationOrigin(request.headers.get("origin"), request.nextUrl.origin)
  ) {
    return Response.json({ detail: "Cross-origin mutation rejected" }, { status: 403 });
  }
  const query = request.nextUrl.searchParams;
  let body: unknown;
  if (["POST", "PATCH", "PUT"].includes(request.method)) {
    const text = await request.text();
    if (text.length > 16_384)
      return Response.json({ detail: "Request too large" }, { status: 413 });
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      return Response.json({ detail: "Invalid JSON" }, { status: 400 });
    }
  }
  if (token.demo === true && process.env.NODE_ENV !== "production")
    return demoResponse(path, request.method, query, body);
  if (!token.backendCookie)
    return Response.json({ detail: "Backend session unavailable" }, { status: 401 });

  const url = new URL(
    `${process.env.BACKEND_API_URL ?? "http://127.0.0.1:8001"}/api/v1/${path.map(encodeURIComponent).join("/")}`,
  );
  url.search = query.toString();
  try {
    const upstream = await fetch(url, {
      method: request.method,
      headers: {
        Cookie: token.backendCookie,
        Accept: path.at(-1) === "diff" ? "text/plain" : "application/json",
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      redirect: "manual",
      signal: AbortSignal.timeout(12_000),
    });
    const contentType = upstream.headers.get("content-type") ?? "application/json";
    return new Response(upstream.status === 204 ? null : await upstream.arrayBuffer(), {
      status: upstream.status,
      headers: { "Content-Type": contentType, "Cache-Control": "no-store" },
    });
  } catch {
    return Response.json({ detail: "Hosted API unavailable" }, { status: 503 });
  }
}

export const GET = forward;
export const POST = forward;
export const DELETE = forward;
