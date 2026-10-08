"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getRepoBranches, startRepoAudit } from "@/lib/api";
import type { Repository } from "@/lib/types";
import { Button } from "@/components/ui/button";

/** Select a live GitHub branch and open a persisted latest-commit audit. */
export function RepositoryAuditControl({
  orgId,
  repo,
  demo = false,
}: {
  orgId: string;
  repo: Repository;
  demo?: boolean;
}) {
  const router = useRouter();
  const [branches, setBranches] = useState<string[]>([]);
  const [branch, setBranch] = useState(repo.default_branch);
  const [nextPage, setNextPage] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);
  const submitting = useRef(false);

  useEffect(() => {
    const current = ++generation.current;
    setBranches([]);
    setBranch(repo.default_branch);
    setNextPage(null);
    setError("");
    setRunning(false);
    submitting.current = false;
    if (!repo.is_active || demo) {
      setLoading(false);
      return;
    }
    setLoading(true);
    void getRepoBranches(orgId, repo.id, 1)
      .then((page) => {
        if (generation.current !== current) return;
        const names = page.items.map((item) => item.name);
        setBranches(names);
        setBranch(names.includes(repo.default_branch) ? repo.default_branch : (names[0] ?? ""));
        setNextPage(page.next_page);
      })
      .catch((caught: unknown) => {
        if (generation.current === current)
          setError(caught instanceof Error ? caught.message : "Could not load branches");
      })
      .finally(() => {
        if (generation.current === current) setLoading(false);
      });
    return () => {
      generation.current = current + 1;
    };
  }, [orgId, repo.id, repo.default_branch, repo.is_active, demo]);

  async function loadMore() {
    if (!nextPage || loading) return;
    const current = generation.current;
    setLoading(true);
    setError("");
    try {
      const page = await getRepoBranches(orgId, repo.id, nextPage);
      if (generation.current !== current) return;
      setBranches((existing) => [
        ...new Set([...existing, ...page.items.map((item) => item.name)]),
      ]);
      setNextPage(page.next_page);
    } catch (caught) {
      if (generation.current === current)
        setError(caught instanceof Error ? caught.message : "Could not load branches");
    } finally {
      if (generation.current === current) setLoading(false);
    }
  }

  async function audit() {
    if (submitting.current || !branch || demo || !repo.is_active || loading) return;
    const current = generation.current;
    submitting.current = true;
    setRunning(true);
    setError("");
    try {
      const result = await startRepoAudit(orgId, repo.id, branch);
      if (generation.current === current)
        router.push(`/dashboard/audits/${encodeURIComponent(result.audit_id)}`);
    } catch (caught) {
      if (generation.current === current)
        setError(caught instanceof Error ? caught.message : "Could not start audit");
    } finally {
      if (generation.current === current) {
        submitting.current = false;
        setRunning(false);
      }
    }
  }

  return (
    <section
      className="mb-6 rounded-xl border border-white/10 bg-white/[.02] p-5"
      aria-label="Start repository audit"
    >
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-56 flex-1">
          <label htmlFor="audit-branch" className="mb-2 block text-xs text-slate-400">
            Branch
          </label>
          <select
            id="audit-branch"
            value={branch}
            onChange={(event) => setBranch(event.target.value)}
            disabled={loading || running || demo || !repo.is_active || !branches.length}
            className="w-full rounded-lg border border-white/15 bg-slate-950 px-3 py-2 text-sm text-slate-100"
          >
            {!branches.length && (
              <option value={branch}>
                {loading ? "Loading branches…" : "No branches available"}
              </option>
            )}
            {branches.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
        {nextPage && (
          <Button variant="outline" disabled={loading || running} onClick={() => void loadMore()}>
            Load more branches
          </Button>
        )}
        <Button
          disabled={loading || running || !branches.length || demo || !repo.is_active}
          onClick={() => void audit()}
        >
          {running ? "Starting audit…" : "Audit now"}
        </Button>
      </div>
      <p className="mt-3 text-xs text-slate-500">
        {demo
          ? "Sign in with GitHub to run an audit."
          : !repo.is_active
            ? "Activate this repository before auditing."
            : "Scans the latest commit changes on the selected branch. Results open automatically."}
      </p>
      {error && (
        <p role="alert" className="mt-3 text-sm text-red-300">
          {error}
        </p>
      )}
    </section>
  );
}
