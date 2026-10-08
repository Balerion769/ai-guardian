"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import {
  ArrowLeft,
  ArrowUpRight,
  Check,
  Copy,
  FileCode2,
  GitPullRequest,
  Timer,
} from "lucide-react";
import { getAudit, getAuditDiff, getRepos } from "@/lib/api";
import { DiffViewer } from "@/components/diff-viewer";
import type { Audit, Repository } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/status-badge";
import { RiskScoreBadge } from "@/components/risk-score-badge";
import { LoadingState, ErrorState } from "@/components/load-state";
import { formatDate } from "@/lib/utils";

const severityTone = {
  HIGH: "border-red-500/25 bg-red-500/10 text-red-300",
  MEDIUM: "border-amber-500/25 bg-amber-500/10 text-amber-300",
  LOW: "border-blue-500/25 bg-blue-500/10 text-blue-300",
};

export default function AuditDetailPage({ params }: { params: Promise<{ auditId: string }> }) {
  const { data: session } = useSession();
  const [route, setRoute] = useState<{ auditId: string } | null>(null);
  const [audit, setAudit] = useState<Audit | null>(null);
  const [repo, setRepo] = useState<Repository | null>(null);
  const [diff, setDiff] = useState<string | null>(null);
  const [diffError, setDiffError] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState<string | null>(null);
  const orgId = session?.orgId;
  const auditId = route?.auditId;
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
    if (!orgId || !auditId) return;
    let active = true;
    getAudit(auditId, orgId)
      .then((value) => {
        if (active) setAudit(value);
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Audit unavailable");
      });
    getAuditDiff(auditId, orgId)
      .then((value) => {
        if (active) setDiff(value);
      })
      .catch(() => {
        if (active) setDiffError("GitHub could not provide this diff right now.");
      });
    return () => {
      active = false;
    };
  }, [orgId, auditId]);
  const auditStatus = audit?.status;
  useEffect(() => {
    if (!orgId || !auditId || !auditStatus || !["QUEUED", "RUNNING"].includes(auditStatus)) return;
    const timer = window.setInterval(() => {
      getAudit(auditId, orgId)
        .then(setAudit)
        .catch(() => undefined);
    }, 5_000);
    return () => window.clearInterval(timer);
  }, [orgId, auditId, auditStatus]);
  const repoId = audit?.repo_id;
  useEffect(() => {
    if (!orgId || !repoId) return;
    getRepos(orgId)
      .then((repos) => setRepo(repos.find((item) => item.id === repoId) ?? null))
      .catch(() => undefined);
  }, [orgId, repoId]);

  async function copyFix(id: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(id);
    } catch {
      setCopied(null);
    }
  }
  if (error) return <ErrorState message={error} />;
  if (!audit) return <LoadingState label="Loading audit..." />;
  const githubUrl = repo
    ? audit.pr_number
      ? `https://github.com/${repo.github_repo_full_name}/pull/${audit.pr_number}`
      : audit.commit_sha
        ? `https://github.com/${repo.github_repo_full_name}/commit/${audit.commit_sha}`
        : null
    : null;
  return (
    <>
      <Link
        href={repo ? `/dashboard/repos/${repo.id}` : "/dashboard"}
        className="mb-6 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-emerald-300"
      >
        <ArrowLeft size={14} /> Back to {repo ? "repository" : "overview"}
      </Link>
      <PageHeader
        eyebrow={`Audit / ${audit.audit_id.slice(0, 12)}`}
        title={repo?.github_repo_full_name ?? "Security audit"}
        description={`Started ${formatDate(audit.created_at)} · ${audit.model_used ?? "Static analysis"} · ${Math.round(audit.latency_ms)} ms`}
        action={
          <div className="flex items-center gap-2">
            <StatusBadge status={audit.status} />
            <RiskScoreBadge score={audit.risk_score} showLabel={false} />
          </div>
        }
      />
      <div className="grid gap-4 sm:grid-cols-4">
        {[
          ["Risk score", audit.risk_score],
          ["High", audit.high_count],
          ["Medium", audit.medium_count],
          ["Low", audit.low_count],
        ].map(([label, value]) => (
          <Card key={label}>
            <CardContent className="p-5">
              <div className="text-xs text-slate-500">{label}</div>
              <div className="mono mt-3 text-2xl font-medium text-white">{value}</div>
            </CardContent>
          </Card>
        ))}
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1.2fr_1fr]">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Code changes</CardTitle>
                <CardDescription>
                  Retrieved from the linked GitHub PR or commit; source is not stored by AI Guardian
                </CardDescription>
              </div>
              {githubUrl && (
                <a
                  href={githubUrl}
                  target="_blank"
                  rel="noreferrer"
                  aria-label="View on GitHub"
                  className="text-slate-500 hover:text-emerald-300"
                >
                  <ArrowUpRight size={16} />
                </a>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {diff ? (
              <DiffViewer diff={diff} />
            ) : (
              <div className="flex min-h-44 flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-white/10 text-center">
                <FileCode2 size={22} className="text-slate-600" />
                <span className="text-sm text-slate-400">
                  {diffError || "No linked diff available"}
                </span>
                <span className="max-w-sm text-xs leading-5 text-slate-600">
                  Audits without a linked GitHub PR or commit cannot show source after submission.
                </span>
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Audit context</CardTitle>
            <CardDescription>{audit.summary}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4 text-xs">
            <div className="flex justify-between border-b border-white/[.06] pb-3">
              <span className="text-slate-500">Branch</span>
              <span className="mono text-slate-300">{audit.branch ?? "—"}</span>
            </div>
            <div className="flex justify-between border-b border-white/[.06] pb-3">
              <span className="text-slate-500">Pull request</span>
              <span className="mono text-slate-300">
                {audit.pr_number ? `#${audit.pr_number}` : "—"}
              </span>
            </div>
            <div className="flex justify-between border-b border-white/[.06] pb-3">
              <span className="text-slate-500">Commit</span>
              <span className="mono text-slate-300">{audit.commit_sha?.slice(0, 10) ?? "—"}</span>
            </div>
            <div className="flex justify-between border-b border-white/[.06] pb-3">
              <span className="text-slate-500">Diff size</span>
              <span className="mono text-slate-300">{audit.diff_size.toLocaleString()} bytes</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Findings</span>
              <span className="mono text-slate-300">{audit.total_findings}</span>
            </div>
            {["QUEUED", "RUNNING"].includes(audit.status) && (
              <div className="flex items-center gap-2 rounded-lg border border-blue-400/20 bg-blue-400/[.05] p-3 text-blue-300">
                <Timer size={14} />
                Refreshing status every 5 seconds
              </div>
            )}
          </CardContent>
        </Card>
      </div>
      <div className="mt-7 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Findings</h2>
          <p className="mt-1 text-xs text-slate-500">
            Each finding includes its location, confidence, and a suggested fix.
          </p>
        </div>
        <span className="mono text-xs text-slate-500">{audit.findings.length} total</span>
      </div>
      <div className="mt-4 space-y-3">
        {audit.findings.map((finding) => (
          <Card key={finding.id}>
            <CardContent className="p-5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-center gap-3">
                  <Badge className={severityTone[finding.severity]}>{finding.severity}</Badge>
                  <h3 className="text-sm font-semibold">{finding.category}</h3>
                </div>
                <span className="mono text-[11px] text-slate-500">
                  {Math.round(finding.confidence * 100)}% confidence
                </span>
              </div>
              <p className="mono mt-3 flex items-center gap-2 text-[11px] text-slate-500">
                <FileCode2 size={13} />
                {finding.file_path ?? "Unknown file"}:{finding.line_number ?? "—"}
              </p>
              <p className="mt-4 text-sm leading-6 text-slate-300">{finding.description}</p>
              <div className="mt-4 rounded-lg border border-emerald-500/15 bg-emerald-500/[.04] p-4">
                <div className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-emerald-300">
                  Recommended fix
                </div>
                <pre className="thin-scroll overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-6 text-slate-200">
                  {finding.remediation}
                </pre>
              </div>
              <div className="mt-4 flex justify-end">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyFix(finding.id, finding.remediation)}
                >
                  {copied === finding.id ? <Check size={13} /> : <Copy size={13} />}
                  {copied === finding.id ? "Copied" : "Copy fix"}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
        {!audit.findings.length && (
          <Card>
            <CardContent className="flex min-h-40 flex-col items-center justify-center text-center">
              <GitPullRequest className="text-emerald-300" size={26} />
              <p className="mt-3 text-sm font-semibold">No findings in this audit</p>
              <p className="mt-1 text-xs text-slate-500">
                A clean scan is a useful signal, but review the change before merging.
              </p>
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}
