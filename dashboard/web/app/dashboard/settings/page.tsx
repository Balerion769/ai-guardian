"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { ArrowUpRight, Building2, CreditCard, Github, KeyRound, ShieldCheck, Users } from "lucide-react";
import { getMembers, getOrg } from "@/lib/api";
import type { Member, Organization } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { LoadingState, ErrorState } from "@/components/load-state";

export default function SettingsPage() {
  const { data: session } = useSession();
  const [state, setState] = useState<{ org: Organization; members: Member[] } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!session?.orgId) return;
    let active = true;
    Promise.all([getOrg(session.orgId), getMembers(session.orgId)])
      .then(([org, members]) => {
        if (active) setState({ org, members });
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Settings unavailable");
      });
    return () => {
      active = false;
    };
  }, [session?.orgId]);
  if (error) return <ErrorState message={error} />;
  if (!state) return <LoadingState label="Loading workspace settings..." />;
  return (
    <>
      <PageHeader
        eyebrow="Workspace administration"
        title="Settings"
        description="Manage your organization, members, access keys, and plan."
      />
      <div className="grid gap-5 lg:grid-cols-[1.35fr_1fr]">
        <div className="space-y-5">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-300">
                  <Building2 size={18} />
                </div>
                <div>
                  <CardTitle>Organization</CardTitle>
                  <CardDescription>Your linked workspace</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4 pt-4">
              <div className="flex justify-between border-b border-white/[.07] pb-3 text-sm">
                <span className="text-slate-500">Name</span>
                <span className="font-medium">{state.org.name}</span>
              </div>
              <div className="flex justify-between border-b border-white/[.07] pb-3 text-sm">
                <span className="text-slate-500">GitHub organization</span>
                <span className="mono text-xs text-slate-300">
                  {state.org.github_slug ?? "Personal workspace"}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-slate-500">Your role</span>
                <Badge className="border-emerald-500/20 bg-emerald-500/[.07] capitalize text-emerald-300">
                  {state.org.role}
                </Badge>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-blue-500/10 p-2 text-blue-300">
                  <Users size={18} />
                </div>
                <div>
                  <CardTitle>Members</CardTitle>
                  <CardDescription>{state.members.length} people in this workspace</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-1 pt-3">
              {state.members.map((member) => (
                <div
                  key={member.user_id}
                  className="flex items-center gap-3 border-b border-white/[.06] py-3 last:border-0"
                >
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-white/[.07] text-xs font-semibold text-slate-300">
                    {(member.login ?? member.user_id).slice(0, 1).toUpperCase()}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs font-semibold text-slate-200">
                      {member.login ?? member.user_id}
                    </div>
                    {member.email && (
                      <div className="truncate text-[11px] text-slate-500">{member.email}</div>
                    )}
                  </div>
                  <Badge className="border-white/10 bg-white/[.04] capitalize text-slate-400">
                    {member.role}
                  </Badge>
                </div>
              ))}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-slate-500/10 p-2 text-slate-300"><Github size={18} /></div>
                <div><CardTitle>GitHub App</CardTitle><CardDescription>Audit pull requests automatically</CardDescription></div>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <p className="text-xs leading-6 text-slate-400">Install the app to create a security check run for each opened or updated pull request.</p>
              <Link href="/dashboard/settings/github" className="mt-5 inline-flex items-center gap-2 text-xs font-semibold text-emerald-300 hover:text-emerald-200">Configure GitHub App <ArrowUpRight size={13} /></Link>
            </CardContent>
          </Card>
        </div>
        <div className="space-y-5">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-amber-500/10 p-2 text-amber-300">
                  <CreditCard size={18} />
                </div>
                <div>
                  <CardTitle>Plan & billing</CardTitle>
                  <CardDescription>Your current audit allocation</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="flex items-end justify-between">
                <div>
                  <div className="text-2xl font-semibold capitalize">{state.org.plan}</div>
                  <div className="mt-1 text-xs text-slate-500">
                    {state.org.plan === "team"
                      ? "Unlimited"
                      : state.org.daily_limit.toLocaleString()}{" "}
                    audits per day
                  </div>
                </div>
                <ShieldCheck size={26} className="text-emerald-300/50" />
              </div>
              <div className="mt-6 border-t border-white/[.07] pt-4">
                <Link
                  href="/dashboard/settings/billing"
                  className="inline-flex items-center gap-2 text-xs font-semibold text-emerald-300 hover:text-emerald-200"
                >
                  Open billing
                  <ArrowUpRight size={13} />
                </Link>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-violet-500/10 p-2 text-violet-300">
                  <KeyRound size={18} />
                </div>
                <div>
                  <CardTitle>API access</CardTitle>
                  <CardDescription>Issue or revoke keys for CI integrations</CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <p className="text-xs leading-6 text-slate-400">
                Keys authorize audit submissions against this organization. The secret is only shown
                once when created.
              </p>
              <Link
                href="/dashboard/settings/api-keys"
                className="mt-5 inline-flex items-center gap-2 text-xs font-semibold text-emerald-300 hover:text-emerald-200"
              >
                Manage API keys <ArrowUpRight size={13} />
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
