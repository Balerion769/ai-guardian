"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import {
  ArrowRight,
  ArrowUpRight,
  GitBranch,
  ShieldAlert,
  ShieldCheck,
  ScanLine,
} from "lucide-react";
import { getAudits, getRepos, getStats } from "@/lib/api";
import type { Audit, Repository, Stats } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RiskOverTimeChart, FindingsByCategory } from "@/components/charts";
import { RiskScoreBadge } from "@/components/risk-score-badge";
import { StatusBadge } from "@/components/status-badge";
import { LoadingState, ErrorState } from "@/components/load-state";
import { formatRelative } from "@/lib/utils";

export default function OverviewPage() {
  const { data: session } = useSession();
  const orgId = session?.orgId;
  const [data, setData] = useState<{
    stats: Stats;
    repos: Repository[];
    audits: Audit[];
    auditTotal: number;
  } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!orgId) return;
    let active = true;
    setData(null);
    setError("");
    Promise.all([getStats(orgId), getRepos(orgId), getAudits(orgId)])
      .then(([stats, repos, audits]) => {
        if (active) setData({ stats, repos, audits: audits.items, auditTotal: audits.total });
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Data unavailable");
      });
    return () => {
      active = false;
    };
  }, [orgId]);
  const metrics = useMemo(() => {
    if (!data) return null;
    const completed = data.audits.filter((item) => ["PASSED", "FAILED"].includes(item.status));
    const latest = new Map<string, Audit>();
    for (const item of completed)
      if (item.repo_id && !latest.has(item.repo_id)) latest.set(item.repo_id, item);
    const since = Date.now() - 7 * 86_400_000;
    const recentDays = data.stats.risk_over_time.filter(
      (day) => new Date(day.date).getTime() >= since,
    );
    const total = recentDays.reduce((sum, day) => sum + day.audit_count, 0);
    return {
      repos: data.repos.length,
      highOpen: [...latest.values()]
        .flatMap((item) => item.findings)
        .filter((item) => item.severity === "HIGH" && !item.is_fixed).length,
      avg: total
        ? Math.round(
            recentDays.reduce((sum, day) => sum + day.average_risk_score * day.audit_count, 0) /
              total,
          )
        : 0,
      audits: data.auditTotal,
    };
  }, [data]);

  if (error) return <ErrorState message={error} retry={() => window.location.reload()} />;
  if (!data || !metrics) return <LoadingState />;
  const repoNames = new Map(data.repos.map((repo) => [repo.id, repo.github_repo_full_name]));
  const cards = [
    {
      label: "Total repositories",
      value: metrics.repos,
      icon: GitBranch,
      note: "Linked to this workspace",
      tone: "text-emerald-300",
    },
    {
      label: "High issues open",
      value: metrics.highOpen,
      icon: ShieldAlert,
      note: "In latest repository audits",
      tone: "text-red-300",
    },
    {
      label: "Average risk score",
      value: metrics.avg,
      icon: ScanLine,
      note: "Across visible audits",
      tone: "text-amber-300",
    },
    {
      label: "Audits · last 7 days",
      value: metrics.audits,
      icon: ShieldCheck,
      note: "Completed and in progress",
      tone: "text-blue-300",
    },
  ];
  return (
    <>
      <PageHeader
        eyebrow="Security pulse · last 7 days"
        title="Your security posture, at a glance"
        description="A clear view of what changed, what needs attention, and where risk is trending."
        action={
          <Link
            href="/dashboard/repos"
            className="inline-flex items-center gap-2 text-xs font-semibold text-emerald-300 hover:text-emerald-200"
          >
            Explore repositories <ArrowUpRight size={14} />
          </Link>
        }
      />
      {session?.demo && (
        <div className="mb-6 flex items-center gap-3 rounded-lg border border-emerald-500/20 bg-emerald-500/[.05] px-4 py-3 text-xs text-emerald-200">
          <span className="h-2 w-2 rounded-full bg-emerald-300" />
          Interactive demo · sample audits and API keys are not connected to your repositories.
        </div>
      )}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {cards.map(({ label, value, icon: Icon, note, tone }) => (
          <Card key={label} className="relative overflow-hidden">
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-emerald-400/40 to-transparent" />
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <span className="text-xs font-medium text-slate-400">{label}</span>
                <div className={`rounded-lg bg-white/[.04] p-2 ${tone}`}>
                  <Icon size={16} />
                </div>
              </div>
              <div className="mono mt-5 text-3xl font-medium tracking-tight text-white">
                {value}
              </div>
              <div className="mt-2 text-[11px] text-slate-500">{note}</div>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1.45fr_1fr]">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Risk over time</CardTitle>
                <CardDescription>Daily average risk score · lower is better</CardDescription>
              </div>
              <span className="mono text-[10px] text-slate-600">0—100</span>
            </div>
          </CardHeader>
          <CardContent>
            <RiskOverTimeChart data={data.stats.risk_over_time} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Findings by category</CardTitle>
            <CardDescription>Where issues are concentrated</CardDescription>
          </CardHeader>
          <CardContent>
            <FindingsByCategory data={data.stats.findings_by_category} />
          </CardContent>
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>Recent audits</CardTitle>
            <CardDescription>Latest security reviews across linked repositories</CardDescription>
          </div>
          <Link
            href="/dashboard/repos"
            className="flex items-center gap-1 text-xs font-semibold text-emerald-300 hover:text-emerald-200"
          >
            All repos <ArrowRight size={14} />
          </Link>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Repository</TableHead>
              <TableHead>Result</TableHead>
              <TableHead>Risk score</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>When</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.audits.slice(0, 6).map((audit) => (
              <TableRow key={audit.audit_id}>
                <TableCell className="font-medium text-slate-200">
                  {repoNames.get(audit.repo_id ?? "") ?? "Unlinked audit"}
                </TableCell>
                <TableCell>
                  <StatusBadge status={audit.status} />
                </TableCell>
                <TableCell>
                  <RiskScoreBadge score={audit.risk_score} showLabel={false} />
                </TableCell>
                <TableCell className="mono text-xs text-slate-400">
                  {audit.total_findings}
                </TableCell>
                <TableCell className="text-xs text-slate-500">
                  {formatRelative(audit.created_at)}
                </TableCell>
                <TableCell className="text-right">
                  <Link
                    href={`/dashboard/audits/${audit.audit_id}`}
                    aria-label={`View audit ${audit.audit_id}`}
                    className="text-slate-500 hover:text-emerald-300"
                  >
                    <ArrowUpRight size={16} />
                  </Link>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {data.audits.length === 0 && (
          <p className="p-10 text-center text-sm text-slate-500">
            No audits yet. Submit a change with your API key to see activity here.
          </p>
        )}
      </Card>
    </>
  );
}
