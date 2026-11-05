import { Suspense } from "react"
import { redirect } from "next/navigation"
import { connection } from "next/server"
import { ApiError, apiGet } from "@/lib/api/client"
import type { AlertState } from "@/lib/api/types"
import { Skeleton } from "@/components/ui/skeleton"
import { EmptyState } from "@/components/empty-state"
import { AlertSettings } from "@/components/preferences/alert-settings"

export const metadata = { title: "Preferences" }

async function PreferencesContent({
  searchParams,
}: {
  searchParams: Promise<{ welcome?: string }>
}) {
  const { welcome } = await searchParams
  await connection()
  let state: AlertState | null = null
  try {
    state = await apiGet<AlertState>("/api/v1/alerts")
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) redirect("/login")
  }

  return state ? (
    <AlertSettings state={state} welcome={welcome === "1"} />
  ) : (
    <EmptyState
      title="Could not load alert settings"
      description="The API may be unavailable. Try again in a moment."
    />
  )
}

export default function PreferencesPage({
  searchParams,
}: {
  searchParams: Promise<{ welcome?: string }>
}) {
  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Preferences</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          Choose how Threatwatch alerts you about technologies you follow.
        </p>
      </div>
      <Suspense fallback={<Skeleton className="h-64 max-w-2xl" />}>
        <PreferencesContent searchParams={searchParams} />
      </Suspense>
    </div>
  )
}
