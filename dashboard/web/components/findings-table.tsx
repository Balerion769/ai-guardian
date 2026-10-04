"use client";

import { useMemo, useState } from "react";
import { Check, Copy, ExternalLink, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { filterFindings } from "@/lib/findings";
import type { Finding } from "@/lib/types";

const tones = {
  HIGH: "border-red-500/25 bg-red-500/10 text-red-300",
  MEDIUM: "border-amber-500/25 bg-amber-500/10 text-amber-300",
  LOW: "border-blue-500/25 bg-blue-500/10 text-blue-300",
};

export function FindingsTable({
  findings,
  compact = false,
}: {
  findings: Finding[];
  compact?: boolean;
}) {
  const [severity, setSeverity] = useState("all");
  const [category, setCategory] = useState("all");
  const [file, setFile] = useState("");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [copied, setCopied] = useState(false);
  const categories = useMemo(
    () => [...new Set(findings.map((item) => item.category))].sort(),
    [findings],
  );
  const visible = filterFindings(findings, { severity, category, file });

  async function copyFix() {
    if (!selected) return;
    try {
      await navigator.clipboard.writeText(selected.remediation);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  return (
    <>
      <div className="flex flex-wrap gap-2 border-b border-white/[.07] px-5 py-4">
        <label className="sr-only" htmlFor="finding-severity">
          Severity
        </label>
        <select
          id="finding-severity"
          value={severity}
          onChange={(event) => setSeverity(event.target.value)}
          className="h-9 rounded-lg border border-white/10 bg-[#202630] px-3 text-xs text-slate-200"
        >
          <option value="all">All severities</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <label className="sr-only" htmlFor="finding-category">
          Category
        </label>
        <select
          id="finding-category"
          value={category}
          onChange={(event) => setCategory(event.target.value)}
          className="h-9 max-w-[220px] rounded-lg border border-white/10 bg-[#202630] px-3 text-xs text-slate-200"
        >
          <option value="all">All categories</option>
          {categories.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <div className="relative min-w-[170px] flex-1 sm:max-w-[260px]">
          <Search className="absolute left-3 top-2.5 text-slate-500" size={14} />
          <label className="sr-only" htmlFor="finding-file">
            File
          </label>
          <input
            id="finding-file"
            value={file}
            onChange={(event) => setFile(event.target.value)}
            placeholder="Filter by file..."
            className="h-9 w-full rounded-lg border border-white/10 bg-[#202630] pl-9 pr-3 text-xs text-slate-200 placeholder:text-slate-500"
          />
        </div>
        <span className="ml-auto self-center text-xs text-slate-500">
          {visible.length} finding{visible.length === 1 ? "" : "s"}
        </span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Severity</TableHead>
            <TableHead>Category</TableHead>
            <TableHead>File</TableHead>
            <TableHead>Line</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {visible.map((item) => (
            <TableRow key={item.id}>
              <TableCell>
                <Badge className={tones[item.severity]}>{item.severity}</Badge>
              </TableCell>
              <TableCell className="font-medium text-slate-200">{item.category}</TableCell>
              <TableCell
                className="mono max-w-[230px] truncate text-xs text-slate-400"
                title={item.file_path ?? item.line_reference}
              >
                {item.file_path ?? "—"}
              </TableCell>
              <TableCell className="mono text-xs text-slate-400">
                {item.line_number ?? "—"}
              </TableCell>
              <TableCell>
                <span className={item.is_fixed ? "text-emerald-300" : "text-slate-400"}>
                  {item.is_fixed ? "Fixed" : "Open"}
                </span>
              </TableCell>
              <TableCell className="text-right">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setCopied(false);
                    setSelected(item);
                  }}
                >
                  View fix <ExternalLink size={12} />
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {visible.length === 0 && (
        <div className="p-12 text-center text-sm text-slate-500">
          No findings match these filters.
        </div>
      )}
      <Dialog
        open={selected !== null}
        onOpenChange={(open) => {
          if (!open) setSelected(null);
        }}
      >
        <DialogContent>
          <DialogTitle className="text-lg font-semibold">{selected?.category}</DialogTitle>
          <DialogDescription className="mt-1 text-sm text-slate-400">
            {selected?.file_path ?? "Source location"}:{selected?.line_number ?? "—"} ·{" "}
            {selected?.severity} · {Math.round((selected?.confidence ?? 0) * 100)}% confidence
          </DialogDescription>
          <p className="mt-5 text-sm leading-6 text-slate-300">{selected?.description}</p>
          <div className="mt-5 rounded-lg border border-emerald-500/15 bg-emerald-500/[.05] p-4">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-emerald-300">
              Suggested remediation
            </div>
            <pre className="thin-scroll overflow-x-auto whitespace-pre-wrap break-words font-mono text-xs leading-6 text-slate-200">
              {selected?.remediation}
            </pre>
          </div>
          <div className="mt-5 flex justify-end">
            <Button variant="outline" onClick={copyFix}>
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? "Copied" : "Copy fix"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
