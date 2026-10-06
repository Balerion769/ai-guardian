import Link from "next/link";
import { ArrowUpRight, CheckCircle2, Github, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { GithubConnection } from "@/components/github-connection";

export default function GithubAppSettingsPage() {
  const configured = process.env.GITHUB_APP_INSTALL_URL || process.env.NEXT_PUBLIC_GITHUB_APP_INSTALL_URL || "";
  const installUrl = /^https:\/\/github\.com\/apps\/[a-z0-9-]+\/installations\/new$/.test(configured) ? configured : null;
  return (
    <>
      <div className="mb-8 flex items-end justify-between gap-4">
        <div>
          <div className="mono mb-2 text-[10px] uppercase tracking-[.2em] text-emerald-300/70">Integrations</div>
          <h1 className="text-2xl font-semibold tracking-tight text-white">GitHub App</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">Run audits automatically when a pull request opens or receives new commits.</p>
        </div>
        <Github size={28} className="text-slate-500" />
      </div>
      <div className="grid gap-5 lg:grid-cols-[1.2fr_.8fr]">
        <Card>
          <CardHeader>
            <CardTitle>Install AI Guardian</CardTitle>
            <CardDescription>Grant repository access to the GitHub App, then select which repositories it may audit.</CardDescription>
          </CardHeader>
          <CardContent>
            {installUrl ? <Link href={installUrl} className="inline-flex items-center gap-2 rounded-lg bg-emerald-400 px-4 py-2.5 text-xs font-bold text-slate-950 hover:bg-emerald-300">
              Install GitHub App <ArrowUpRight size={14} />
            </Link> : <p>GitHub App installation is not configured. Contact your deployment administrator.</p>}
            <GithubConnection />
            <p className="mt-4 text-xs leading-6 text-slate-500">The app requests contents: read, pull requests: read/write, and checks: write. The webhook verifies every delivery signature before downloading a diff.</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>What happens on a PR</CardTitle>
            <CardDescription>Each event is isolated to this organization.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 text-xs text-slate-400">
            <div className="flex gap-2"><CheckCircle2 size={15} className="mt-0.5 text-emerald-300" />The signed webhook fetches only the PR diff.</div>
            <div className="flex gap-2"><CheckCircle2 size={15} className="mt-0.5 text-emerald-300" />The worker stores findings and metadata under your organization.</div>
            <div className="flex gap-2"><ShieldCheck size={15} className="mt-0.5 text-emerald-300" />A HIGH result creates a failing AI Guardian check run.</div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
