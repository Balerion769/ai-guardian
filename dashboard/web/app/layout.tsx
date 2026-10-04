import type { Metadata } from "next";
import "@/app/globals.css";

export const metadata: Metadata = {
  title: "AI Guardian — Security intelligence",
  description: "Security findings, repository risk, and audit history for your engineering team.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen antialiased">{children}</body>
    </html>
  );
}
