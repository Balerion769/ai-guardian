"use client";

import { useEffect, useMemo, useState } from "react";
import { Button } from "@/components/ui/button";

const PAGE_LINES = 500;

/** Render bounded pages of a patch while keeping all downloaded lines accessible. */
export function DiffViewer({ diff }: { diff: string }) {
  const lines = useMemo(() => diff.split("\n"), [diff]);
  const [page, setPage] = useState(0);
  useEffect(() => setPage(0), [diff]);
  const lastPage = Math.max(0, Math.ceil(lines.length / PAGE_LINES) - 1);
  const current = Math.min(page, lastPage);
  const start = current * PAGE_LINES;
  const end = Math.min(start + PAGE_LINES, lines.length);
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
        <span aria-live="polite">
          Lines {start + 1}–{end} of {lines.length}
        </span>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            aria-label="Previous diff page"
            disabled={current === 0}
            onClick={() => setPage(current - 1)}
          >
            Previous
          </Button>
          <Button
            size="sm"
            variant="outline"
            aria-label="Next diff page"
            disabled={current === lastPage}
            onClick={() => setPage(current + 1)}
          >
            Next
          </Button>
        </div>
      </div>
      <pre
        key={current}
        aria-label="Code diff"
        className="thin-scroll max-h-[540px] overflow-auto rounded-lg border border-white/[.08] bg-[#0d1218] p-4 font-mono text-[11px] leading-6 text-slate-300"
      >
        {lines.slice(start, end).map((line, index) => (
          <div
            key={start + index}
            className={
              line.startsWith("+") && !line.startsWith("+++")
                ? "bg-emerald-500/[.08] text-emerald-200"
                : line.startsWith("-") && !line.startsWith("---")
                  ? "bg-red-500/[.08] text-red-200"
                  : ""
            }
          >
            {line || " "}
          </div>
        ))}
      </pre>
    </div>
  );
}
