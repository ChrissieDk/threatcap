import { Suspense } from "react"
import { cookies } from "next/headers"
import { Landing } from "@/components/landing/landing"
import { OverviewContent } from "@/components/overview/overview-content"
import { hasSessionCookie } from "@/lib/auth"

export default function Page({
  searchParams,
}: {
  searchParams: Promise<{ scope?: string }>
}) {
  return (
    <Suspense fallback={null}>
      <Home searchParams={searchParams} />
    </Suspense>
  )
}

async function Home({ searchParams }: { searchParams: Promise<{ scope?: string }> }) {
  const signedIn = hasSessionCookie((await cookies()).getAll())
  if (!signedIn) {
    return <Landing />
  }
  const { scope } = await searchParams
  return <OverviewContent scope={scope} />
}
