"use client"

import { useEffect } from "react"
import { TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <div className="border-line flex flex-col items-center justify-center gap-3 rounded-md border border-dashed px-6 py-16 text-center">
      <TriangleAlert className="text-severity-high size-5" aria-hidden />
      <p className="text-sm font-medium">Something went wrong</p>
      <p className="text-muted-foreground max-w-sm text-xs">
        The dashboard could not load. The API may be unavailable or still
        starting up.
      </p>
      <Button variant="outline" size="sm" onClick={reset}>
        Try again
      </Button>
    </div>
  )
}
