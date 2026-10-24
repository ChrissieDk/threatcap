import { Suspense } from "react"
import { redirect } from "next/navigation"
import { ApiError, apiGet } from "@/lib/api/client"
import type { Technology } from "@/lib/api/types"
import { TechSearch } from "@/components/technologies/tech-search"
import { FollowButton } from "@/components/technologies/follow-button"
import { EmptyState } from "@/components/empty-state"
import { Skeleton } from "@/components/ui/skeleton"

async function TechnologyList({ search }: { search: string }) {
  const path = search
    ? `/api/v1/technologies?search=${encodeURIComponent(search)}`
    : "/api/v1/technologies"
  let items: Technology[] = []
  try {
    items = await apiGet<Technology[]>(path)
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
    return (
      <EmptyState
        title="Could not load technologies"
        description="The API may be unavailable. Try again in a moment."
      />
    )
  }

  if (items.length === 0) {
    return (
      <EmptyState
        title="No technologies found"
        description={
          search
            ? `Nothing matches "${search}". Try a different search term.`
            : "No technologies are being tracked yet."
        }
      />
    )
  }

  return (
    <ul className="border-line divide-y divide-line rounded-md border">
      {items.map((t) => (
        <li
          key={t.slug}
          className="flex items-center gap-3 px-3 py-2.5"
        >
          <div className="min-w-0 flex-1">
            <p className="truncate text-[13px] font-medium">{t.name}</p>
            <p className="text-muted-foreground font-mono text-[11px]">{t.slug}</p>
          </div>
          <span className="text-muted-foreground text-xs">{t.type}</span>
          {t.ecosystem && (
            <span className="border-line bg-surface-2 rounded-md border px-1.5 py-0.5 text-[11px]">
              {t.ecosystem}
            </span>
          )}
          <FollowButton slug={t.slug} following={t.following} />
        </li>
      ))}
    </ul>
  )
}

function Fallback() {
  return (
    <div className="flex flex-col gap-2">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton key={i} className="h-11 w-full" />
      ))}
    </div>
  )
}

export default async function TechnologiesPage({
  searchParams,
}: {
  searchParams: Promise<{ search?: string }>
}) {
  const { search } = await searchParams
  const q = search?.trim() ?? ""

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-base font-semibold">Technologies</h1>
          <p className="text-muted-foreground mt-0.5 text-xs">
            Languages, frameworks, and tools you can follow for targeted
            vulnerability alerts.
          </p>
        </div>
        <TechSearch key={q} />
      </div>
      <Suspense key={q} fallback={<Fallback />}>
        <TechnologyList search={q} />
      </Suspense>
    </div>
  )
}
