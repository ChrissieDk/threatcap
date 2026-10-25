import { Suspense } from "react"
import Link from "next/link"
import { redirect } from "next/navigation"
import { connection } from "next/server"
import { ApiError, apiGet } from "@/lib/api/client"
import type { DashboardSummary, SecurityIncidentItem } from "@/lib/api/types"
import { IncidentList } from "@/components/incidents/incident-list"
import { EmptyState } from "@/components/empty-state"
import { Skeleton } from "@/components/ui/skeleton"

export const metadata = { title: "Incidents" }

async function tryGet<T>(path: string): Promise<T | null> {
  try {
    return await apiGet<T>(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return null
  }
}

async function IncidentFeed() {
  await connection()

  const [items, summary] = await Promise.all([
    tryGet<SecurityIncidentItem[]>("/api/v1/incidents?following=true&days=30&limit=50"),
    tryGet<DashboardSummary>("/api/v1/dashboard/summary?days=7"),
  ])
  const hasFollows = (summary?.followedCount ?? 0) > 0

  if (items === null) {
    return (
      <EmptyState
        title="Incidents unavailable"
        description="Vendor status feeds could not be loaded. Try refreshing."
      />
    )
  }

  if (!hasFollows) {
    return (
      <div className="flex flex-col gap-2">
        <EmptyState
          title="No technologies followed yet"
          description="Follow GitHub, npm, PyPI, Cloudflare, Docker, or packages in those ecosystems to see live vendor incidents."
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
    )
  }

  if (items.length === 0) {
    return (
      <EmptyState
        title="Nothing happening in your stack"
        description="No vendor outages or degradations matched technologies you follow in the last 30 days."
      />
    )
  }

  return <IncidentList items={items} />
}

function Fallback() {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: 6 }).map((_, i) => (
        <Skeleton key={i} className="h-14 w-full" />
      ))}
    </div>
  )
}

export default function IncidentsPage() {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Incidents</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Live vendor status for technologies you follow, from public status pages.
        </p>
      </div>
      <Suspense fallback={<Fallback />}>
        <IncidentFeed />
      </Suspense>
    </div>
  )
}
