"use client";

import { useState } from "react";
import { Check, Copy, KeyRound, Plus, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { createApiKey } from "@/lib/api";

export function ApiKeyCreateModal({ orgId, onCreated }: { orgId: string; onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [rawKey, setRawKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  function changeOpen(next: boolean) {
    setOpen(next);
    if (!next) {
      setRawKey(null);
      setName("");
      setError("");
      setCopied(false);
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      const created = await createApiKey(orgId, name.trim());
      setRawKey(created.key);
      onCreated();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not create key");
    } finally {
      setLoading(false);
    }
  }

  async function copy() {
    if (!rawKey) return;
    try {
      await navigator.clipboard.writeText(rawKey);
      setCopied(true);
    } catch {
      setError("Clipboard unavailable. Select and copy the key manually.");
    }
  }

  return (
    <>
      <Button onClick={() => changeOpen(true)}>
        <Plus size={15} />
        Create API key
      </Button>
      <Dialog open={open} onOpenChange={changeOpen}>
        <DialogContent>
          {!rawKey ? (
            <>
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-300">
                <KeyRound size={20} />
              </div>
              <DialogTitle className="text-xl font-semibold">Create API key</DialogTitle>
              <DialogDescription className="mt-1 text-sm text-slate-400">
                Use this key for CI and API integrations. It inherits your organization&apos;s audit
                quota.
              </DialogDescription>
              <form onSubmit={submit} className="mt-6 space-y-5">
                <div>
                  <label
                    htmlFor="key-name"
                    className="mb-2 block text-xs font-semibold text-slate-300"
                  >
                    Key name
                  </label>
                  <input
                    id="key-name"
                    required
                    maxLength={120}
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    placeholder="GitHub Actions"
                    className="h-10 w-full rounded-lg border border-white/15 bg-white/[.04] px-3 text-sm text-white placeholder:text-slate-500"
                  />
                </div>
                {error && (
                  <p role="alert" className="text-xs text-red-300">
                    {error}
                  </p>
                )}
                <div className="flex justify-end gap-2">
                  <Button type="button" variant="ghost" onClick={() => changeOpen(false)}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={loading || !name.trim()}>
                    {loading ? "Creating..." : "Create key"}
                  </Button>
                </div>
              </form>
            </>
          ) : (
            <>
              <div className="mb-4 flex h-10 w-10 items-center justify-center rounded-xl bg-amber-500/10 text-amber-300">
                <TriangleAlert size={20} />
              </div>
              <DialogTitle className="text-xl font-semibold">Your new API key</DialogTitle>
              <DialogDescription className="mt-1 text-sm text-amber-200">
                Copy now, you won&apos;t see it again.
              </DialogDescription>
              <div className="mt-5 flex items-center gap-2 rounded-lg border border-amber-400/20 bg-black/30 p-3">
                <code className="thin-scroll min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-xs text-slate-100">
                  {rawKey}
                </code>
                <Button variant="outline" size="icon" aria-label="Copy API key" onClick={copy}>
                  {copied ? <Check size={15} /> : <Copy size={15} />}
                </Button>
              </div>
              {error && (
                <p role="alert" className="mt-3 text-xs text-red-300">
                  {error}
                </p>
              )}
              <div className="mt-6 flex justify-end">
                <Button onClick={() => changeOpen(false)}>Done</Button>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}
