"use client";

import { signIn } from "next-auth/react";
import { ArrowRight, Github } from "lucide-react";
import { Button } from "@/components/ui/button";

export function LoginActions({ demo }: { demo: boolean }) {
  return (
    <div className="space-y-3">
      <Button
        variant="outline"
        className="h-12 w-full justify-between px-4"
        onClick={() => signIn("github", { callbackUrl: "/dashboard" })}
        disabled={demo}
      >
        <span className="flex items-center gap-3">
          <Github size={18} />
          Sign in with GitHub
        </span>
        <ArrowRight size={16} />
      </Button>
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
