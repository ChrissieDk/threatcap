"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { ChevronDown } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { REQUEST_HEADER, endSession } from "@/lib/auth"
import type { TriageStatus } from "@/lib/api/types"

const LABELS: Record<TriageStatus, string> = {
  Acknowledged: "Acknowledged",
  Snoozed: "Snoozed",
  Ignored: "Ignored",
}

/** Mark a finding acknowledged, snoozed or ignored, or reopen it. Triaged findings drop out of counts and alerts. */
export function FindingTriage({
  projectId,
  vulnerabilityId,
  triage,
}: {
  projectId: string
  vulnerabilityId: string
  triage: TriageStatus | null
}) {
  const router = useRouter()
  const [busy, setBusy] = useState(false)
  const [failed, setFailed] = useState(false)

  async function send(method: "PUT" | "DELETE", body?: { status: TriageStatus; snoozeDays?: number }) {
    setBusy(true)
    setFailed(false)
    try {
      const res = await fetch(`/api/v1/projects/${projectId}/findings/${vulnerabilityId}/triage`, {
        method,
        headers: { [REQUEST_HEADER]: "1", ...(body ? { "Content-Type": "application/json" } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      })
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return
      }
      if (!res.ok) {
        setFailed(true)
        return
      }
      router.refresh()
    } catch {
      setFailed(true)
    } finally {
      setBusy(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          type="button"
          size="sm"
          variant={triage ? "secondary" : "ghost"}
          disabled={busy}
          aria-label={triage ? `Triage: ${LABELS[triage]}. Change` : "Triage this finding"}
          className="shrink-0"
        >
          {failed ? "Try again" : triage ? LABELS[triage] : "Triage"}
          <ChevronDown aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="text-xs">
        <DropdownMenuItem className="text-xs" onSelect={() => send("PUT", { status: "Acknowledged" })}>Acknowledge (working on it)</DropdownMenuItem>
        <DropdownMenuItem className="text-xs" onSelect={() => send("PUT", { status: "Snoozed", snoozeDays: 7 })}>Snooze 7 days</DropdownMenuItem>
        <DropdownMenuItem className="text-xs" onSelect={() => send("PUT", { status: "Snoozed", snoozeDays: 30 })}>Snooze 30 days</DropdownMenuItem>
        <DropdownMenuItem className="text-xs" onSelect={() => send("PUT", { status: "Snoozed", snoozeDays: 90 })}>Snooze 90 days</DropdownMenuItem>
        <DropdownMenuItem className="text-xs" onSelect={() => send("PUT", { status: "Ignored" })}>Ignore (does not apply)</DropdownMenuItem>
        {triage && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem className="text-xs" onSelect={() => send("DELETE")}>Reopen</DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
