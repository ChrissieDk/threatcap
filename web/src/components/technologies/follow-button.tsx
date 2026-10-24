"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Button } from "@/components/ui/button"
import { REQUEST_HEADER, endSession } from "@/lib/auth"

export function FollowButton({
  slug,
  following,
  ecosystem,
  packageName,
  name,
}: {
  slug?: string
  following: boolean
  ecosystem?: string
  packageName?: string
  name?: string
}) {
  const router = useRouter()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const labelName = name ?? slug ?? packageName ?? "technology"

  async function toggle() {
    setPending(true)
    setError(null)
    try {
      const res = await sendFollowRequest({ slug, following, ecosystem, packageName })
      if (res.status === 401) {
        await endSession()
        router.push("/login")
        router.refresh()
        return
      }
      if (!res.ok) {
        setError(following ? "Could not unfollow." : "Could not follow.")
        return
      }
      router.refresh()
    } catch {
      setError("Could not reach the server.")
    } finally {
      setPending(false)
    }
  }

  const label = pending
    ? following
      ? "Unfollowing…"
      : "Following…"
    : following
      ? "Unfollow"
      : "Follow"

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        type="button"
        size="sm"
        variant={following ? "outline" : "default"}
        aria-pressed={following}
        aria-label={following ? `Unfollow ${labelName}` : `Follow ${labelName}`}
        disabled={pending}
        className={
          following
            ? "text-muted-foreground hover:border-severity-critical hover:bg-severity-critical/10 hover:text-severity-critical"
            : undefined
        }
        onClick={() => void toggle()}
      >
        {label}
      </Button>
      {error && (
        <p role="alert" className="text-severity-critical text-[11px]">
          {error}
        </p>
      )}
    </div>
  )
}

async function sendFollowRequest({
  slug,
  following,
  ecosystem,
  packageName,
}: {
  slug?: string
  following: boolean
  ecosystem?: string
  packageName?: string
}): Promise<Response> {
  if (following) {
    if (!slug) throw new Error("Missing slug")
    return fetch(`/api/v1/follows/${encodeURIComponent(slug)}`, {
      method: "DELETE",
      headers: { [REQUEST_HEADER]: "1" },
    })
  }

  if (slug) {
    return fetch(`/api/v1/follows/${encodeURIComponent(slug)}`, {
      method: "POST",
      headers: { [REQUEST_HEADER]: "1" },
    })
  }

  return fetch("/api/v1/follows", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      [REQUEST_HEADER]: "1",
    },
    body: JSON.stringify({ ecosystem, packageName }),
  })
}
