"use client";

import {useEffect, useState} from "react";
import {useSession} from "next-auth/react";
import Link from "next/link";
import {connectInstallation, getInstallation} from "@/lib/api";
import {Button} from "@/components/ui/button";

/** Verify the untrusted GitHub setup callback against the active workspace. */
export function GithubConnection() {
  const {data: session} = useSession();
  const [installed, setInstalled] = useState<number | null>(null);
  const [candidate, setCandidate] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const raw = new URLSearchParams(window.location.search).get("installation_id");
    const id = Number(raw);
    setCandidate(Number.isSafeInteger(id) && id > 0 ? id : null);
    if (!session?.orgId) return;
    let active = true;
    setInstalled(null);
    getInstallation(session.orgId).then(result => {if (active) setInstalled(result.installation_id);})
      .catch(caught => {if (active) setError(caught instanceof Error ? caught.message : "Connection unavailable");});
    return () => {active = false;};
  }, [session?.orgId]);
  async function connect() {
    if (!session?.orgId || !candidate) return;
    setBusy(true); setError("");
    try {setInstalled((await connectInstallation(session.orgId, candidate)).installation_id);}
    catch (caught) {setError(caught instanceof Error ? caught.message : "Connection failed");}
    finally {setBusy(false);}
  }
  return <div className="mt-4 space-y-3 text-sm">
    <p>{installed ? "GitHub App connected to this workspace." : "Install the App, then connect it to this workspace on your return."}</p>
    {candidate && candidate !== installed && <Button disabled={busy} onClick={connect}>{busy ? "Verifying..." : "Connect installation to workspace"}</Button>}
    {error && <p role="alert" className="text-red-300">{error}</p>}
    <Link href="/dashboard/repos" className="text-emerald-300 underline">Choose repositories to audit</Link>
  </div>;
}
