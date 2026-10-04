import { getServerSession } from "next-auth";
import { redirect } from "next/navigation";
import { authConfigured, authOptions } from "@/lib/auth";
import { AppShell } from "@/components/app-shell";

export const dynamic = "force-dynamic";

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  if (!authConfigured()) redirect("/login");
  const session = await getServerSession(authOptions);
  if (!session?.orgId) redirect("/login");
  return <AppShell initialSession={session}>{children}</AppShell>;
}
