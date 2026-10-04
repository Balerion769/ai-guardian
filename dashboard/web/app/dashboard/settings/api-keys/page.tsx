"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { ArrowLeft, KeyRound, ShieldAlert, Trash2 } from "lucide-react";
import { getApiKeys, revokeApiKey } from "@/lib/api";
import type { ApiKeyRecord } from "@/lib/types";
import { PageHeader } from "@/components/page-header";
import { ApiKeyCreateModal } from "@/components/api-key-create-modal";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { LoadingState, ErrorState } from "@/components/load-state";

export default function ApiKeysPage() {
  const { data: session } = useSession();
  const orgId = session?.orgId;
  const [keys, setKeys] = useState<ApiKeyRecord[] | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const refresh = useCallback(() => {
    if (orgId)
      getApiKeys(orgId)
        .then(setKeys)
        .catch((caught) =>
          setError(caught instanceof Error ? caught.message : "API keys unavailable"),
        );
  }, [orgId]);
  useEffect(() => {
    refresh();
  }, [refresh]);

  async function revoke(record: ApiKeyRecord) {
    if (
      !orgId ||
      !window.confirm(`Revoke ${record.name}? Integrations using this key will stop working.`)
    )
      return;
    setBusy(record.id);
    setError("");
    try {
      await revokeApiKey(orgId, record.id);
      refresh();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not revoke key");
    } finally {
      setBusy(null);
    }
  }
  if (error && !keys) return <ErrorState message={error} />;
  if (!keys || !orgId) return <LoadingState label="Loading API keys..." />;
  return (
    <>
      <Link
        href="/dashboard/settings"
        className="mb-6 inline-flex items-center gap-2 text-xs text-slate-500 hover:text-emerald-300"
      >
        <ArrowLeft size={14} /> Workspace settings
      </Link>
      <PageHeader
        eyebrow="Access management"
        title="API keys"
        description="Manage the credentials used by CI and automation to submit audits."
        action={<ApiKeyCreateModal orgId={orgId} onCreated={refresh} />}
      />
      <div className="mb-5 flex items-start gap-3 rounded-lg border border-amber-500/20 bg-amber-500/[.05] p-4 text-xs leading-5 text-amber-200">
        <ShieldAlert size={16} className="mt-0.5 shrink-0" /> Store keys in your CI secret manager.
        Raw values are displayed only at creation and are never available from this list.
      </div>
      {error && (
        <p role="alert" className="mb-4 text-xs text-red-300">
          {error}
        </p>
      )}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-300">
              <KeyRound size={18} />
            </div>
            <div>
              <CardTitle>Issued keys</CardTitle>
              <CardDescription>
                {keys.filter((key) => !key.revoked).length} active credential
                {keys.filter((key) => !key.revoked).length === 1 ? "" : "s"}
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Prefix</TableHead>
              <TableHead>Last four</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {keys.map((record) => (
              <TableRow key={record.id}>
                <TableCell className="font-semibold text-slate-200">{record.name}</TableCell>
                <TableCell className="mono max-w-[280px] truncate text-xs text-slate-500">
                  {record.prefix}
                </TableCell>
                <TableCell className="mono text-xs text-slate-300">••••{record.last4}</TableCell>
                <TableCell>
                  <Badge
                    className={
                      record.revoked
                        ? "border-slate-500/20 bg-slate-500/10 text-slate-400"
                        : "border-emerald-500/20 bg-emerald-500/10 text-emerald-300"
                    }
                  >
                    {record.revoked ? "Revoked" : "Active"}
                  </Badge>
                </TableCell>
                <TableCell className="text-right">
                  {!record.revoked && (
                    <Button
                      variant="danger"
                      size="sm"
                      disabled={busy === record.id}
                      onClick={() => revoke(record)}
                    >
                      <Trash2 size={13} />
                      Revoke
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {!keys.length && (
          <div className="p-12 text-center text-sm text-slate-500">
            No keys yet. Create one to connect a CI workflow.
          </div>
        )}
      </Card>
    </>
  );
}
