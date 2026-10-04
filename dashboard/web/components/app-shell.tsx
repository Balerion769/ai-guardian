"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { SessionProvider, signOut, useSession } from "next-auth/react";
import type { Session } from "next-auth";
import {
  Activity,
  Bell,
  ChevronDown,
  CircleHelp,
  Github,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  Shield,
  X,
} from "lucide-react";
import { getOrgs } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { cn } from "@/lib/utils";

const nav = [
  { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/repos", label: "Repositories", icon: Github },
  { href: "/dashboard/settings/api-keys", label: "API keys", icon: KeyRound },
  { href: "/dashboard/settings/billing", label: "Billing", icon: Settings },
  { href: "/dashboard/settings/github", label: "GitHub App", icon: Github },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
];

function ShellContent({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { data: session, update } = useSession();
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [switching, setSwitching] = useState(false);
  useEffect(() => {
    getOrgs()
      .then(setOrgs)
      .catch(() => setOrgs([]));
  }, [session?.orgId]);
  const title = pathname.startsWith("/dashboard/settings/billing")
    ? "Billing"
    : pathname.startsWith("/dashboard/settings/github")
      ? "GitHub App"
    : pathname.startsWith("/dashboard/settings/api-keys")
      ? "API keys"
      : pathname.startsWith("/dashboard/settings")
        ? "Settings"
        : pathname.startsWith("/dashboard/audits/")
          ? "Audit details"
          : pathname.startsWith("/dashboard/repos/")
            ? "Repository details"
            : pathname.startsWith("/dashboard/repos")
              ? "Repositories"
              : "Overview";

  async function selectOrg(orgId: string) {
    if (orgId === session?.orgId) return;
    setSwitching(true);
    try {
      const updated = await update({ orgId });
      if (updated?.orgId === orgId) {
        router.push("/dashboard");
        router.refresh();
      }
    } finally {
      setSwitching(false);
    }
  }

  const sidebar = (
    <>
      <div className="flex h-16 items-center gap-3 border-b border-white/[.07] px-6">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-emerald-400/30 bg-emerald-400/10 text-emerald-300">
          <Shield size={18} strokeWidth={2.4} />
        </div>
        <span className="text-sm font-bold tracking-tight">AI Guardian</span>
        <span className="mono ml-auto rounded border border-emerald-500/25 bg-emerald-500/[.07] px-1.5 py-0.5 text-[9px] text-emerald-300">
          BETA
        </span>
      </div>
      <div className="px-4 pt-6">
        <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">
          Workspace
        </div>
        <div className="relative">
          <select
            aria-label="Organization"
            value={session?.orgId ?? ""}
            disabled={switching}
            onChange={(event) => selectOrg(event.target.value)}
            className="h-11 w-full appearance-none rounded-lg border border-white/10 bg-[#1b232c] pl-3 pr-9 text-xs font-semibold text-slate-200"
          >
            {orgs.length ? (
              orgs.map((org) => (
                <option key={org.id} value={org.id}>
                  {org.name}
                </option>
              ))
            ) : (
              <option value={session?.orgId ?? ""}>
                {session?.demo ? "Acme Engineering" : "Your workspace"}
              </option>
            )}
          </select>
          <ChevronDown
            size={14}
            className="pointer-events-none absolute right-3 top-3.5 text-slate-500"
          />
        </div>
      </div>
      <nav aria-label="Main navigation" className="mt-8 space-y-1 px-3">
        <div className="mb-3 px-4 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">
          Monitor
        </div>
        {nav.slice(0, 2).map(({ href, label, icon: Icon }) => {
          const active = href === "/dashboard" ? pathname === href : pathname.startsWith(href);
          return (
            <Link
              onClick={() => setMobileOpen(false)}
              key={href}
              href={href}
              className={cn(
                "flex h-10 items-center gap-3 rounded-lg px-4 text-xs font-medium transition-colors",
                active
                  ? "border border-emerald-400/10 bg-emerald-400/[.09] text-emerald-300"
                  : "text-slate-400 hover:bg-white/[.04] hover:text-white",
              )}
            >
              <Icon size={16} />
              {label}
            </Link>
          );
        })}
        <div className="mb-3 mt-8 px-4 text-[10px] font-semibold uppercase tracking-[.18em] text-slate-600">
          Workspace
        </div>
        {nav.slice(2).map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              onClick={() => setMobileOpen(false)}
              key={href}
              href={href}
              className={cn(
                "flex h-10 items-center gap-3 rounded-lg px-4 text-xs font-medium transition-colors",
                active
                  ? "border border-emerald-400/10 bg-emerald-400/[.09] text-emerald-300"
                  : "text-slate-400 hover:bg-white/[.04] hover:text-white",
              )}
            >
              <Icon size={16} />
              {label}
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto px-4 pb-5">
        <div className="rounded-xl border border-white/[.07] bg-white/[.025] p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <Activity size={14} className="text-emerald-300" /> Continuous visibility
          </div>
          <p className="mt-2 text-[11px] leading-5 text-slate-500">
            Your audit history updates as the worker completes each scan.
          </p>
        </div>
        <a
          href="https://github.com/Balerion769/ai-guardian/issues"
          target="_blank"
          rel="noreferrer"
          className="mt-4 flex items-center gap-2 px-2 text-xs text-slate-500 hover:text-slate-300"
        >
          <CircleHelp size={14} /> Help & feedback
        </a>
      </div>
    </>
  );

  return (
    <div className="min-h-screen bg-[#10151b]">
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 flex-col border-r border-white/[.07] bg-[#141a21] lg:flex">
        {sidebar}
      </aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            aria-label="Close menu"
            className="absolute inset-0 bg-black/70"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="relative flex h-full w-64 flex-col bg-[#141a21]">{sidebar}</aside>
        </div>
      )}
      <div className="lg:pl-60">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-white/[.07] bg-[#10151b]/90 px-5 backdrop-blur-md sm:px-8">
          <div className="flex items-center gap-3">
            <button
              className="text-slate-400 lg:hidden"
              aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
            </button>
            <span className="text-sm font-semibold">{title}</span>
            <span className="hidden text-slate-700 sm:inline">/</span>
            <span className="mono hidden text-[11px] text-slate-500 sm:inline">
              security workspace
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/[.06] px-3 py-1.5 text-[10px] font-semibold text-emerald-300 sm:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />{" "}
              {session?.demo ? "DEMO DATA" : "CONNECTED"}
            </span>
            <Bell size={17} className="text-slate-500" />
            <div className="flex h-8 w-8 items-center justify-center rounded-full border border-emerald-400/20 bg-emerald-400/10 text-xs font-bold text-emerald-300">
              {session?.user?.name?.slice(0, 1).toUpperCase() ?? "A"}
            </div>
            <button
              aria-label="Sign out"
              onClick={() => signOut({ callbackUrl: "/login" })}
              className="text-slate-500 hover:text-white"
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1480px] px-5 py-7 sm:px-8 sm:py-9">{children}</main>
      </div>
    </div>
  );
}

export function AppShell({
  initialSession,
  children,
}: {
  initialSession: Session;
  children: React.ReactNode;
}) {
  return (
    <SessionProvider session={initialSession}>
      <ShellContent>{children}</ShellContent>
    </SessionProvider>
  );
}
