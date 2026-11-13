import { cookies } from "next/headers"
import { AppShell } from "@/components/layout/app-shell"
import { hasSessionCookie } from "@/lib/auth"

export async function ShellGate({ children }: { children: React.ReactNode }) {
  const signedIn = hasSessionCookie((await cookies()).getAll())
  return <AppShell signedIn={signedIn}>{children}</AppShell>
}
