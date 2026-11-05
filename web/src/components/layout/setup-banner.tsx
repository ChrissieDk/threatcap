"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { BellRing, X } from "lucide-react"
import type { AlertState } from "@/lib/api/types"

const DISMISS_KEY = "threatwatch.setup-banner.dismissed"

/** Nudges users who have not connected any alert channel yet. */
export function SetupBanner() {
  const pathname = usePathname()
  const [needsSetup, setNeedsSetup] = useState(false)

  useEffect(() => {
    try {
      if (localStorage.getItem(DISMISS_KEY) === "1") return
    } catch {}
    let cancelled = false
    fetch("/api/v1/alerts")
      .then(async (res) => {
        if (!res.ok) return
        const state = (await res.json()) as AlertState
        if (!cancelled) setNeedsSetup(state.channels.length === 0)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  if (!needsSetup || pathname.startsWith("/preferences")) return null

  return (
    <div
      role="region"
      aria-label="Alert setup"
      className="border-line bg-surface mb-4 flex items-center gap-3 rounded-md border px-3 py-2 text-xs"
    >
      <BellRing className="text-primary size-4 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1">
        You are not getting alerts yet.{" "}
        <Link href="/preferences?welcome=1" className="text-primary font-medium underline-offset-2 hover:underline">
          Set up alerts in under a minute
        </Link>
      </p>
      <button
        type="button"
        aria-label="Dismiss"
        className="text-muted-foreground hover:text-foreground"
        onClick={() => {
          try {
            localStorage.setItem(DISMISS_KEY, "1")
          } catch {}
          setNeedsSetup(false)
        }}
      >
        <X className="size-4" aria-hidden />
      </button>
    </div>
  )
}
