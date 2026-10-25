"use client"

import { useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { RefreshCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { formatRelativeTime } from "@/lib/formatters"
import { REQUEST_HEADER, endSession } from "@/lib/auth"
import { cn } from "@/lib/utils"
import type { IngestionSyncStatus } from "@/lib/api/types"

const SOURCE_LABELS: Record<string, string> = {
  osv: "OSV",
  "cisa-kev": "CISA KEV",
  epss: "EPSS",
  statuspage: "status pages",
}

export function LastSyncControl({
  lastSyncAt,
  hasError,
}: {
  lastSyncAt: string | null
  hasError: boolean
}) {
  const router = useRouter()
  const [status, setStatus] = useState<IngestionSyncStatus | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const wasRunning = useRef(false)

  const running = pending || status?.running === true

  useEffect(() => {
    let cancelled = false

    async function tick() {
      const next = await readStatus()
      if (cancelled || !next) return
      if (next.running) wasRunning.current = true
      setStatus(next)
      if (!next.running && wasRunning.current) {
        wasRunning.current = false
        router.refresh()
      }
    }

    void tick()
    if (!running) {
      return () => {
        cancelled = true
      }
    }

    const timer = setInterval(() => void tick(), 3000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [running, router])

  const sourceLabel = status?.currentSource
    ? (SOURCE_LABELS[status.currentSource] ?? status.currentSource)
    : null

  async function refresh() {
    setError(null)
    setPending(true)
    try {
      const res = await fetch("/api/v1/ingestion/sync", {
        method: "POST",
        headers: { [REQUEST_HEADER]: "1" },
        signal: AbortSignal.timeout(20_000),
      })
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return
      }
      if (res.status === 429) {
        setError("Too many refreshes. Wait a minute.")
        return
      }
      if (!res.ok) {
        setError("Could not start a sync.")
        return
      }
      const body = (await res.json()) as IngestionSyncStatus
      if (body.running) wasRunning.current = true
      setStatus(body)
    } catch {
      setError("Could not reach the server.")
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="min-w-0">
      <p className="text-muted-foreground text-[11px] font-medium tracking-wide uppercase">
        Last sync
      </p>
      <p className="mt-0.5 flex items-center gap-1.5 text-lg font-semibold tabular-nums">
        {lastSyncAt ? formatRelativeTime(lastSyncAt) : "Never"}
        <Button
          type="button"
          size="sm"
          variant="outline"
          aria-label="Refresh vulnerability data"
          aria-busy={running}
          disabled={running}
          className="h-6 px-2"
          onClick={() => void refresh()}
        >
          <RefreshCw
            data-icon="inline-start"
            className={cn("size-3.5", running && "animate-spin")}
            aria-hidden
          />
          Refresh
        </Button>
      </p>
      {error ? (
        <p role="alert" className="text-severity-critical mt-1 text-[11px] font-normal">
          {error}
        </p>
      ) : running ? (
        <p className="text-muted-foreground mt-1 text-[11px] font-normal">
          {sourceLabel ? `Updating ${sourceLabel}…` : "Updating vulnerability feeds…"}
        </p>
      ) : hasError ? (
        <p className="text-amber mt-1 text-[11px] font-normal">sync issues</p>
      ) : !lastSyncAt ? (
        <p className="text-amber mt-1 text-[11px] font-normal">no successful sync yet</p>
      ) : null}
    </div>
  )
}

async function readStatus(): Promise<IngestionSyncStatus | null> {
  try {
    const res = await fetch("/api/v1/ingestion/sync", {
      signal: AbortSignal.timeout(20_000),
    })
    if (!res.ok) return null
    return (await res.json()) as IngestionSyncStatus
  } catch {
    return null
  }
}
