"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { ArrowLeft, ArrowUpRight, GitBranch } from "lucide-react";
import { getAudits, getRepos } from "@/lib/api";
import type { Audit, CategoryCount, DailyRisk, Repository } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { RepositoryAuditControl } from "@/components/repository-audit-control";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskOverTimeChart, FindingsByCategory } from "@/components/charts";
import { FindingsTable } from "@/components/findings-table";
import { RiskScoreBadge } from "@/components/risk-score-badge";
import { StatusBadge } from "@/components/status-badge";
import { LoadingState, ErrorState } from "@/components/load-state";
import { formatDate, formatRelative } from "@/lib/utils";

export default function RepositoryPage({ params }: { params: Promise<{ repoId: string }> }) {
  const { data: session } = useSession();
  const [route, setRoute] = useState<{ repoId: string } | null>(null);
  const [state, setState] = useState<{ repo: Repository; audits: Audit[] } | null>(null);
  const [error, setError] = useState("");
  const repoId = route?.repoId;
  useEffect(() => {
    let active = true;
    void params.then((resolved) => {
      if (active) setRoute(resolved);
    });
    return () => {
      active = false;
    };
  }, [params]);
  useEffect(() => {
    if (!session?.orgId || !repoId) return;
    let active = true;
    Promise.all([getRepos(session.orgId), getAudits(session.orgId, { repoId, timeRange: "90d" })])
      .then(([repos, audits]) => {
        const repo = repos.find((entry) => entry.id === repoId);
        if (active)
          repo
            ? setState({ repo, audits: audits.items })
            : setError("Repository not found in this workspace.");
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Repository unavailable");
      });
    return () => {
      active = false;
    };
  }, [session?.orgId, repoId]);
  const report = useMemo(() => {
    if (!state) return null;
    const groups = new Map<string, number[]>();
    const categories = new Map<string, number>();
    for (const audit of state.audits) {
      if (["PASSED", "FAILED"].includes(audit.status)) {
        const day = audit.created_at.slice(0, 10);
        groups.set(day, [...(groups.get(day) ?? []), audit.risk_score]);
      }
      for (const finding of audit.findings)
        categories.set(finding.category, (categories.get(finding.category) ?? 0) + 1);
    }
    const daily: DailyRisk[] = [...groups]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, scores]) => ({
        date,
        average_risk_score: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
        audit_count: scores.length,
      }));
    const categoryData: CategoryCount[] = [...categories].map(([category, count]) => ({
      category,
      count,
    }));
    return { daily, categoryData };
  }, [state]);
  if (error) return <ErrorState message={error} />;
  if (!state || !report) return <LoadingState label="Loading repository..." />;
  const latest = state.audits[0];
  return (
    <>
      <Link
        href="/dashboard/repos"
        className="mb-6 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-emerald-300"
      >
        <ArrowLeft size={14} /> All repositories
      </Link>
      <PageHeader
        eyebrow="Repository intelligence"
        title={state.repo.github_repo_full_name}
        description={`Default branch ${state.repo.default_branch} · Last audited ${formatRelative(state.repo.last_audit_at)}`}
        action={
          latest && (
            <div className="flex items-center gap-3">
              <StatusBadge status={latest.status} />
              <RiskScoreBadge score={latest.risk_score} />
            </div>
          )
        }
      />
      {session?.orgId && (
        <RepositoryAuditControl
          key={`${session.orgId}:${state.repo.id}`}
          orgId={session.orgId}
          repo={state.repo}
          demo={session.demo}
        />
      )}
      <div className="grid gap-4 sm:grid-cols-3">
        <Card>
          <CardContent className="p-5">
            <div className="text-xs text-slate-500">Audits · 90 days</div>
            <div className="mono mt-3 text-2xl text-white">{state.audits.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <div className="text-xs text-slate-500">Open high findings</div>
            <div className="mono mt-3 text-2xl text-red-300">
              {latest?.findings.filter((item) => item.severity === "HIGH" && !item.is_fixed)
                .length ?? 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <div className="text-xs text-slate-500">Latest audit</div>
            <div className="mono mt-3 text-lg text-white">{formatDate(latest?.created_at)}</div>
          </CardContent>
        </Card>
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Risk over time</CardTitle>
            <CardDescription>Daily average for this repository</CardDescription>
          </CardHeader>
          <CardContent>
            <RiskOverTimeChart data={report.daily} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Findings by category</CardTitle>
            <CardDescription>Across visible audit history</CardDescription>
          </CardHeader>
          <CardContent>
            <FindingsByCategory data={report.categoryData} />
          </CardContent>
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>Latest findings</CardTitle>
          <CardDescription>Filter by severity, category, and file</CardDescription>
        </CardHeader>
        <FindingsTable findings={latest?.findings ?? []} />
      </Card>
      <Card className="mt-5">
        <CardHeader>
          <CardTitle>Audit history</CardTitle>
          <CardDescription>Every scan tells the story of this repository</CardDescription>
        </CardHeader>
        <div className="space-y-0 px-5 pb-4">
          {state.audits.map((audit, index) => (
            <div
              key={audit.audit_id}
              className="relative flex gap-4 border-l border-white/10 pb-6 pl-6 last:border-transparent last:pb-2"
            >
              <span
                className={`absolute -left-[5px] top-1 h-2.5 w-2.5 rounded-full border-2 border-[#1a2028] ${audit.status === "FAILED" ? "bg-red-400" : "bg-emerald-400"}`}
              />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <span className="mono text-xs text-slate-500">
                      #{state.audits.length - index}
                    </span>
                    <StatusBadge status={audit.status} />
                    <span className="text-xs text-slate-500">
                      {formatRelative(audit.created_at)}
                    </span>
                  </div>
                  <Link
                    href={`/dashboard/audits/${audit.audit_id}`}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-emerald-300"
                  >
                    View audit <ArrowUpRight size={13} />
                  </Link>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  {audit.total_findings} findings · risk score {audit.risk_score}
                  {audit.pr_number ? ` · PR #${audit.pr_number}` : ""}
                </p>
              </div>
            </div>
          ))}
          {!state.audits.length && (
            <div className="flex items-center gap-2 py-6 text-sm text-slate-500">
              <GitBranch size={16} /> No audits for this repository yet.
            </div>
          )}
        </div>
      </Card>
    </>
  );
}
