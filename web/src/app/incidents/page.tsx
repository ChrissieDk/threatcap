import Link from "next/link"
import { redirect } from "next/navigation"
import { connection } from "next/server"
import { ApiError, apiGet } from "@/lib/api/client"
import type { ActNowItem, DashboardSummary } from "@/lib/api/types"
import { ActNowStack } from "@/components/overview/act-now-stack"
import { EmptyState } from "@/components/empty-state"

export const metadata = { title: "Incidents" }

async function tryGet<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return null
  }
}

export default async function IncidentsPage() {
  await connection()

  const [actNow, summary] = await Promise.all([
    tryGet<ActNowItem[]>("/api/v1/dashboard/act-now?top=20&days=30"),
    tryGet<DashboardSummary>("/api/v1/dashboard/summary?days=7"),
  ])
  const hasFollows = (summary?.followedCount ?? 0) > 0

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Incidents</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Prioritized vulnerabilities affecting your followed technologies, last 30 days.
        </p>
      </div>

      {actNow === null ? (
        <EmptyState
          title="Incidents unavailable"
          description="The priority list could not be loaded. Try refreshing."
        />
      ) : !hasFollows ? (
        <div className="flex flex-col gap-2">
          <EmptyState
            title="No technologies followed yet"
            description="Follow the technologies in your stack to see prioritized incidents that matter most to you."
          />
          <p className="text-muted-foreground text-xs">
            <Link
              href="/technologies"
              className="text-primary hover:underline focus-visible:ring-primary/50 rounded-sm focus-visible:ring-2 focus-visible:outline-none"
            >
              Browse technologies to follow →
            </Link>
          </p>
        </div>
      ) : actNow.length === 0 ? (
        <EmptyState
          title="No active incidents"
          description="Nothing in your stack needs attention right now — no recent disclosures or newly exploited vulnerabilities with a known fix priority."
        />
      ) : (
        <ActNowStack items={actNow} />
      )}
    </div>
  )
}
