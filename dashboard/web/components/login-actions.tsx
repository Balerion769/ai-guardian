"use client";

import { signIn } from "next-auth/react";
import { ArrowRight, Github } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useState } from "react";

export function LoginActions({ demo }: { demo: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function beginGithubLogin(): Promise<void> {
    setBusy(true);
    setError("");
    try {
      const ready = await fetch("/api/auth/backend-ready", { cache: "no-store", signal: AbortSignal.timeout(60_000) });
      if (!ready.ok) throw new Error("Backend unavailable");
      await signIn("github", { callbackUrl: "/dashboard" });
    } catch {
      setError("The sign-in server is starting or unavailable. Please try again in a minute.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-3">
      <Button
        variant="outline"
        className="h-12 w-full justify-between px-4"
        onClick={beginGithubLogin}
        disabled={demo || busy}
      >
        <span className="flex items-center gap-3">
          <Github size={18} />
          {busy ? "Preparing GitHub sign-in…" : "Sign in with GitHub"}
        </span>
        <ArrowRight size={16} />
      </Button>
      {busy ? <p role="status" className="text-sm text-slate-400">Waking the sign-in server; this can take about a minute.</p> : null}
      {error ? <p role="alert" className="text-sm text-amber-300">{error}</p> : null}
      {demo ? (
        <>
          <Button
            className="h-12 w-full justify-between px-4"
            onClick={() => signIn("demo", { callbackUrl: "/dashboard" })}
          >
            <span>Explore interactive demo</span>
            <ArrowRight size={16} />
          </Button>
          <p className="text-center text-xs text-slate-500">
            GitHub OAuth is not configured. Demo data stays local to this development server.
          </p>
        </>
      ) : null}
    </div>
  );
}
