"use client"

import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useEffect, useState } from "react"
import { Input } from "@/components/ui/input"

export function TechSearch() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const initial = searchParams.get("search") ?? ""
  const [value, setValue] = useState(initial)

  useEffect(() => {
    const timer = setTimeout(() => {
      const trimmed = value.trim()
      const current = searchParams.get("search") ?? ""
      if (trimmed !== current) {
        router.replace(
          trimmed ? `${pathname}?search=${encodeURIComponent(trimmed)}` : pathname,
          { scroll: false }
        )
      }
    }, 400)
    return () => clearTimeout(timer)
  }, [value, pathname, router, searchParams])

  return (
    <Input
      value={value}
      onChange={(e) => setValue(e.target.value)}
      placeholder="Search technologies…"
      aria-label="Search technologies"
      className="w-64"
    />
  )
}
