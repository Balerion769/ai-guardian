"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { ArrowUpRight, GitBranch, Search } from "lucide-react";
import { getAudits, getRepos } from "@/lib/api";
import type { Audit, Repository } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { RiskSparkline } from "@/components/charts";
import { RiskScoreBadge } from "@/components/risk-score-badge";
import { LoadingState, ErrorState } from "@/components/load-state";
import { formatRelative } from "@/lib/utils";
import { GithubRepoPicker } from "@/components/github-repo-picker";

export default function RepositoriesPage() {
  const { data: session } = useSession();
  const [state, setState] = useState<{ repos: Repository[]; audits: Audit[] } | null>(null);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  useEffect(() => {
    if (!session?.orgId) return;
    let active = true;
    setState(null);
    Promise.all([getRepos(session.orgId), getAudits(session.orgId, { timeRange: "90d" })])
      .then(([repos, audits]) => {
        if (active) setState({ repos, audits: audits.items });
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Repositories unavailable");
      });
    return () => {
      active = false;
    };
  }, [session?.orgId]);
  const filtered = useMemo(
    () =>
      state?.repos.filter((repo) =>
        repo.github_repo_full_name.toLowerCase().includes(search.toLowerCase()),
      ) ?? [],
    [state, search],
  );
  if (error) return <ErrorState message={error} />;
  if (!state) return <LoadingState label="Loading repositories..." />;
  return (
    <>
      <PageHeader
        eyebrow="Your codebase"
        title="Repositories"
        description="Monitor risk and audit activity across every linked repository."
        action={
          <Badge className="border-white/10 bg-white/[.04] px-3 py-1.5 text-slate-300">
            <GitBranch size={12} />
            {state.repos.length} linked
          </Badge>
        }
      />
      <GithubRepoPicker linked={state.repos.map(repo => repo.github_repo_full_name)} onLinked={() => {
        if (session?.orgId) getRepos(session.orgId).then(repos => setState(current => current ? {...current, repos} : current)).catch(caught => setError(caught instanceof Error ? caught.message : "Refresh failed"));
      }} />
      <Card>
        <CardContent className="flex items-center justify-between gap-3 border-b border-white/[.07] p-4">
          <div className="relative w-full max-w-xs">
            <Search size={15} className="absolute left-3 top-2.5 text-slate-500" />
            <label className="sr-only" htmlFor="repo-search">
              Search repositories
            </label>
            <input
              id="repo-search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search repositories..."
              className="h-9 w-full rounded-lg border border-white/10 bg-[#202630] pl-9 pr-3 text-xs text-white placeholder:text-slate-500"
            />
          </div>
          <span className="text-xs text-slate-500">{filtered.length} results</span>
        </CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Repository</TableHead>
              <TableHead>Last audit</TableHead>
              <TableHead>Risk trend · 90d</TableHead>
              <TableHead>Latest risk</TableHead>
              <TableHead>High issues</TableHead>
              <TableHead>Status</TableHead>
              <TableHead />
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map((repo) => {
              const audits = state.audits.filter((audit) => audit.repo_id === repo.id);
              const latest = audits[0];
              const highOpen =
                latest?.findings.filter((item) => item.severity === "HIGH" && !item.is_fixed)
                  .length ?? 0;
              return (
                <TableRow key={repo.id}>
                  <TableCell>
                    <Link
                      href={`/dashboard/repos/${repo.id}`}
                      className="group flex items-center gap-3"
                    >
                      <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-white/10 bg-white/[.04] text-slate-400">
                        <GitBranch size={15} />
                      </span>
                      <span>
                        <span className="block font-semibold text-slate-200 group-hover:text-emerald-300">
                          {repo.github_repo_full_name}
                        </span>
                        <span className="mono mt-0.5 block text-[10px] text-slate-600">
                          {repo.default_branch}
                        </span>
                      </span>
                    </Link>
                  </TableCell>
                  <TableCell className="text-xs text-slate-400">
                    {formatRelative(repo.last_audit_at)}
                  </TableCell>
                  <TableCell>
                    <RiskSparkline
                      scores={audits
                        .slice(0, 9)
                        .reverse()
                        .map((item) => item.risk_score)}
                    />
                  </TableCell>
                  <TableCell>
                    {latest ? (
                      <RiskScoreBadge score={latest.risk_score} showLabel={false} />
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </TableCell>
                  <TableCell
                    className={
                      highOpen
                        ? "mono text-xs font-semibold text-red-300"
                        : "mono text-xs text-slate-400"
                    }
                  >
                    {highOpen}
                  </TableCell>
                  <TableCell>
                    <Badge
                      className={
                        repo.is_active
                          ? "border-emerald-500/20 bg-emerald-500/[.07] text-emerald-300"
                          : "border-slate-500/20 bg-slate-500/[.07] text-slate-400"
                      }
                    >
                      {repo.is_active ? "Active" : "Paused"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/dashboard/repos/${repo.id}`}
                      aria-label={`View ${repo.github_repo_full_name}`}
                      className="text-slate-500 hover:text-emerald-300"
                    >
                      <ArrowUpRight size={16} />
                    </Link>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
        {!filtered.length && (
          <div className="p-12 text-center text-sm text-slate-500">
            No repositories match your search.
          </div>
        )}
      </Card>
    </>
  );
}
