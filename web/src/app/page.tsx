import { Suspense } from "react"
import { OverviewContent } from "@/components/overview/overview-content"
import { OverviewSkeleton } from "@/components/overview/overview-skeleton"

export default function Page({
  searchParams,
}: {
  searchParams: Promise<{ scope?: string }>
}) {
  return (
    <Suspense fallback={<OverviewSkeleton />}>
      <OverviewFromSearchParams searchParams={searchParams} />
    </Suspense>
  )
}

async function OverviewFromSearchParams({
  searchParams,
}: {
  searchParams: Promise<{ scope?: string }>
}) {
  const { scope } = await searchParams
  return <OverviewContent scope={scope} />
}
