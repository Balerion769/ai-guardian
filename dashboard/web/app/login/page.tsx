import { isDemoMode } from "@/lib/auth";
import { LoginActions } from "@/components/login-actions";
import { Activity, ArrowUpRight, Fingerprint, GitBranch, LockKeyhole, Shield } from "lucide-react";

export default async function LoginPage({ searchParams }: { searchParams?: Promise<{ error?: string }> }) {
  const error = (await searchParams)?.error;
  const errorMessage = error === "BackendUnavailable"
    ? "The sign-in server was unavailable. Please try again; your GitHub account has not been blocked."
    : error === "AccessDenied"
      ? "GitHub sign-in could not be completed. Try again and allow the requested GitHub authorization."
      : error ? "Sign-in could not be completed. Please try again." : null;
  return (
    <main className="grid-glow relative flex min-h-screen items-center justify-center overflow-hidden p-5">
      <div className="pointer-events-none absolute -left-24 top-1/3 h-96 w-96 rounded-full bg-emerald-500/[.08] blur-3xl" />
      <div className="relative z-10 grid w-full max-w-5xl overflow-hidden rounded-2xl border border-white/10 bg-[#11171e]/95 shadow-[0_30px_100px_rgba(0,0,0,.45)] lg:grid-cols-[1.15fr_.85fr]">
        <section className="relative hidden min-h-[580px] flex-col justify-between overflow-hidden border-r border-white/10 bg-[#141c23] p-10 lg:flex">
          <div
            className="absolute inset-0 opacity-30"
            style={{
              backgroundImage: "radial-gradient(#5cae88 1px, transparent 1px)",
              backgroundSize: "24px 24px",
              maskImage: "linear-gradient(to bottom, transparent, black 35%, transparent)",
            }}
          />
          <div className="relative">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
                <Shield size={20} strokeWidth={2.3} />
              </div>
              <span className="text-sm font-bold tracking-tight">AI Guardian</span>
            </div>
          </div>
          <div className="relative max-w-md">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-400/[.06] px-3 py-1.5 text-[11px] font-semibold text-emerald-300">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" /> SECURITY INTELLIGENCE FOR
              BUILDERS
            </div>
            <h1 className="text-5xl font-semibold leading-[1.08] tracking-[-.055em]">
              See the risk
              <br />
              <span className="text-gradient">before it ships.</span>
            </h1>
            <p className="mt-6 max-w-sm text-sm leading-7 text-slate-400">
              A single view of your repositories, code audits, and actionable fixes. Every change
              gets a clearer path to production.
            </p>
          </div>
          <div className="relative grid grid-cols-3 gap-3 border-t border-white/10 pt-6 text-xs text-slate-400">
            <span className="flex items-center gap-2">
              <GitBranch size={14} className="text-emerald-300" /> Repository aware
            </span>
            <span className="flex items-center gap-2">
              <Activity size={14} className="text-emerald-300" /> Risk trends
            </span>
            <span className="flex items-center gap-2">
              <Fingerprint size={14} className="text-emerald-300" /> Local first
            </span>
          </div>
        </section>
        <section className="flex min-h-[580px] flex-col justify-center p-8 sm:p-12">
          <div className="mb-10 flex items-center gap-3 lg:hidden">
            <Shield className="text-emerald-300" size={24} />
            <span className="font-bold">AI Guardian</span>
          </div>
          <div className="mb-2 font-mono text-[11px] uppercase tracking-[.18em] text-emerald-300">
            Developer console / Sign in
          </div>
          <h2 className="text-3xl font-semibold tracking-tight">Welcome back</h2>
          <p className="mt-3 text-sm leading-6 text-slate-400">
            Connect your GitHub account to see security posture across every linked repository.
          </p>
          <div className="mt-9">
            {errorMessage ? <p role="alert" className="mb-4 text-sm text-amber-300">{errorMessage}</p> : null}
            <LoginActions demo={isDemoMode} />
          </div>
          <div className="mt-8 flex items-start gap-3 rounded-lg border border-white/[.07] bg-white/[.025] p-4 text-xs leading-5 text-slate-500">
            <LockKeyhole size={16} className="mt-0.5 shrink-0 text-slate-400" />
            <span>
              Sign in with your GitHub account to create your own private workspace. GitHub credentials stay on the server.
            </span>
          </div>
          <div className="mt-12 flex items-center justify-between border-t border-white/[.08] pt-5 text-[11px] text-slate-600">
            <span>© 2026 AI Guardian</span>
            <a
              href="https://github.com/Balerion769/ai-guardian"
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 hover:text-slate-300"
            >
              View project <ArrowUpRight size={12} />
            </a>
          </div>
        </section>
      </div>
    </main>
  );
}
