"use client"

import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"
import { Search } from "lucide-react"
import { Input } from "@/components/ui/input"

export function GlobalSearch() {
  const router = useRouter()
  const [value, setValue] = useState("")

  useEffect(() => {
    const trimmed = value.trim()
    if (!trimmed) return
    const timer = setTimeout(() => {
      router.push(`/vulnerabilities?search=${encodeURIComponent(trimmed)}`)
    }, 400)
    return () => clearTimeout(timer)
  }, [value, router])

  return (
    <div className="relative">
      <Search
        className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2"
        aria-hidden
      />
      <Input
        type="search"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && value.trim()) {
            router.push(
              `/vulnerabilities?search=${encodeURIComponent(value.trim())}`
            )
          }
        }}
        placeholder="Search vulnerabilities…"
        aria-label="Search vulnerabilities"
        className="pl-8"
      />
    </div>
  )
}
