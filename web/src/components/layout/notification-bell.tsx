"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import Link from "next/link"
import { Bell, Flame } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { SeverityBadge } from "@/components/severity-badge"
import { formatRelativeTime } from "@/lib/formatters"
import type { Severity } from "@/lib/api/types"

type NotificationItem = {
  vulnerabilityId: string
  canonicalId: string
  title: string
  severity: Severity
  cvssScore: number | null
  isKnownExploited: boolean
  activityAt: string
  matchedTechnologyName: string
  matchedTechnologySlug: string
}

type NotificationSummary = {
  unreadCount: number
  hasKevUnread: boolean
  items: NotificationItem[]
  generatedAt: string
}

const POLL_INTERVAL_MS = 60_000

export function NotificationBell() {
  const [summary, setSummary] = useState<NotificationSummary | null>(null)
  const [pending, setPending] = useState(false)
  const [open, setOpen] = useState(false)
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const refresh = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/notifications", { cache: "no-store" })
      if (!res.ok) return // 401s are handled by AccountMenu's session flow
      setSummary((await res.json()) as NotificationSummary)
    } catch {
      // Network hiccup; keep the last known state.
    }
  }, [])

  useEffect(() => {
    // Defer the initial load out of the effect body (avoids a synchronous setState
    // cascade flagged by react-hooks/set-state-in-effect); the interval and focus
    // listeners keep it fresh afterwards.
    const initial = setTimeout(() => void refresh(), 0)
    intervalRef.current = setInterval(() => void refresh(), POLL_INTERVAL_MS)
    const onFocus = () => void refresh()
    window.addEventListener("focus", onFocus)
    return () => {
      clearTimeout(initial)
      if (intervalRef.current) clearInterval(intervalRef.current)
      window.removeEventListener("focus", onFocus)
    }
  }, [refresh])

  async function markAllRead() {
    setPending(true)
    try {
      const res = await fetch("/api/v1/notifications/read", { method: "POST" })
      if (res.ok) {
        setSummary((await res.json()) as NotificationSummary)
      }
    } catch {
      // Keep last known state; the next poll will converge.
    } finally {
      setPending(false)
    }
  }

  const unread = summary?.unreadCount ?? 0
  const hasKev = summary?.hasKevUnread ?? false

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon" aria-label="Notifications" className="relative">
          <Bell className="size-4" aria-hidden />
          {unread > 0 && (
            <span
              className={`absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-semibold text-white ${
                hasKev ? "bg-severity-critical" : "bg-primary"
              }`}
            >
              {unread > 20 ? "20+" : unread}
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80 p-0">
        <DropdownMenuLabel className="flex items-center justify-between px-3 pt-2.5">
          <span className="text-foreground text-sm font-semibold">Notifications</span>
          {summary && unread > 0 && (
            <span className="text-muted-foreground text-xs">
              {unread} unread{hasKev ? " · KEV activity" : ""}
            </span>
          )}
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <div className="max-h-96 overflow-y-auto">
          {!summary || summary.items.length === 0 ? (
            <div className="text-muted-foreground px-3 py-8 text-center text-sm">
              No new activity for your follows
            </div>
          ) : (
            summary.items.map((item) => (
              <DropdownMenuItem key={item.vulnerabilityId} asChild className="px-0 py-0">
                <Link
                  href={`/vulnerabilities/${item.vulnerabilityId}`}
                  onClick={() => setOpen(false)}
                  className="hover:bg-surface-2 block px-3 py-2.5"
                >
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    {item.isKnownExploited && (
                      <span className="text-severity-high inline-flex items-center gap-1 text-[11px] font-medium">
                        <Flame className="size-3" aria-hidden />
                        KEV
                      </span>
                    )}
                    <span className="text-muted-foreground ml-auto text-[11px]">
                      {formatRelativeTime(item.activityAt)}
                    </span>
                  </div>
                  <div className="mt-1 truncate text-sm">{item.title}</div>
                  <div className="text-muted-foreground mt-0.5 flex items-center gap-2 text-[11px]">
                    <span className="font-mono">{item.canonicalId}</span>
                    <span>·</span>
                    <span>{item.matchedTechnologyName}</span>
                  </div>
                </Link>
              </DropdownMenuItem>
            ))
          )}
        </div>
        {summary && summary.items.length > 0 && (
          <>
            <DropdownMenuSeparator />
            <div className="p-2">
              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={markAllRead}
                disabled={pending || unread === 0}
              >
                Mark all read
              </Button>
            </div>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
