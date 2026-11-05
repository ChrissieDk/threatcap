"use client"

import { useEffect, useRef, useState } from "react"
import Link from "next/link"
import { useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { REQUEST_HEADER } from "@/lib/auth"

type Status = "pending" | "verified" | "failed"

export function VerifyEmail() {
  const params = useSearchParams()
  const userId = params.get("uid")
  const token = params.get("token")
  const incomplete = !userId || !token
  const [status, setStatus] = useState<Status>(incomplete ? "failed" : "pending")
  const [message, setMessage] = useState<string | null>(
    incomplete ? "This verification link is incomplete." : null
  )
  const started = useRef(false)

  useEffect(() => {
    // Tokens are single-use; guard against React strict-mode double effects.
    if (started.current || !userId || !token) return
    started.current = true
    fetch("/api/v1/auth/verify-email/confirm", {
      method: "POST",
      headers: { "Content-Type": "application/json", [REQUEST_HEADER]: "1" },
      body: JSON.stringify({ userId, token }),
    })
      .then(async (res) => {
        if (res.ok) {
          setStatus("verified")
          return
        }
        const body = (await res.json().catch(() => null)) as { error?: { message?: string } } | null
        setStatus("failed")
        setMessage(body?.error?.message ?? "This verification link is invalid or has expired.")
      })
      .catch(() => {
        setStatus("failed")
        setMessage("Could not reach the server. Try again.")
      })
  }, [userId, token])

  return (
    <main className="flex min-h-screen items-center justify-center px-4">
      <div className="border-line bg-surface w-full max-w-sm rounded-md border p-6 text-center">
        <h1 className="text-base font-semibold">
          {status === "pending" ? "Verifying…" : status === "verified" ? "Email verified" : "Verification failed"}
        </h1>
        {status === "verified" && (
          <p className="text-muted-foreground mt-1 text-xs">You can now receive alerts by email.</p>
        )}
        {status === "failed" && (
          <p role="alert" className="text-muted-foreground mt-1 text-xs">
            {message} Sign in and request a new link from Preferences.
          </p>
        )}
        {status !== "pending" && (
          <Button asChild size="sm" className="mt-4">
            <Link href="/preferences">Go to alert settings</Link>
          </Button>
        )}
      </div>
    </main>
  )
}
