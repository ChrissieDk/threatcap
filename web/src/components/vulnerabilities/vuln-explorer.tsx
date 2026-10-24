"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import {
  createColumnHelper,
  flexRender,
  tableFeatures,
  useTable,
} from "@tanstack/react-table"
import { ArrowDown, ArrowUp, Flame, Wrench } from "lucide-react"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { SeverityBadge } from "@/components/severity-badge"
import { ProductBadge } from "@/components/product-badge"
import { EmptyState } from "@/components/empty-state"
import { formatCvss, formatRelativeTime } from "@/lib/formatters"
import type { VulnerabilityListItem, VulnerabilityListResponse } from "@/lib/api/types"
import { endSession } from "@/lib/auth"

const PAGE_SIZE = 20
const ECOSYSTEMS = ["Npm", "NuGet", "PyPI", "Maven", "Cargo", "Go"]

const features = tableFeatures({})
const col = createColumnHelper<typeof features, VulnerabilityListItem>()
const EMPTY_ITEMS: VulnerabilityListItem[] = []

function param(sp: URLSearchParams, key: string): string {
  return sp.get(key) ?? ""
}

export function VulnExplorer() {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const search = param(searchParams, "search")
  const severity = param(searchParams, "severity")
  const ecosystem = param(searchParams, "ecosystem")
  const kev = param(searchParams, "kev")
  const fix = param(searchParams, "fix")
  const followingOnly = param(searchParams, "following") === "true"
  const tech = param(searchParams, "tech")
  const page = Math.max(1, Number(searchParams.get("page") ?? "1") || 1)
  const sort = param(searchParams, "sort") || "-publishedAt"

  const [searchInput, setSearchInput] = useState(search)
  const [lastSearch, setLastSearch] = useState(search)
  if (search !== lastSearch) {
    setLastSearch(search)
    setSearchInput(search)
  }

  const queryKey = [search, severity, ecosystem, kev, fix, followingOnly, tech, page, sort].join("|")
  const [result, setResult] = useState<{
    key: string
    data: VulnerabilityListResponse | null
  }>({ key: "", data: null })
  const loading = result.key !== queryKey
  const failed = result.key === queryKey && result.data === null

  const replaceParams = useCallback(
    (updates: Record<string, string>) => {
      const sp = new URLSearchParams(searchParams.toString())
      for (const [k, v] of Object.entries(updates)) {
        if (v) sp.set(k, v)
        else sp.delete(k)
      }
      if (!("page" in updates)) sp.delete("page")
      router.replace(`${pathname}?${sp.toString()}`, { scroll: false })
    },
    [router, pathname, searchParams]
  )

  useEffect(() => {
    const trimmed = searchInput.trim()
    const timer = setTimeout(() => {
      if (trimmed !== search) {
        replaceParams({ search: trimmed })
      }
    }, 400)
    return () => clearTimeout(timer)
  }, [searchInput, search, replaceParams])

  useEffect(() => {
    const sp = new URLSearchParams()
    if (search) sp.set("search", search)
    if (severity) sp.set("severity", severity)
    if (ecosystem) sp.set("ecosystem", ecosystem)
    if (kev) sp.set("kev", kev)
    if (fix) sp.set("fix", fix)
    if (followingOnly) sp.set("following", "true")
    if (tech) sp.set("tech", tech)
    sp.set("page", String(page))
    sp.set("pageSize", String(PAGE_SIZE))
    sp.set("sort", sort)

    let cancelled = false
    fetch(`/api/v1/vulnerabilities?${sp.toString()}`, {
      signal: AbortSignal.timeout(20_000),
    })
      .then(async (res) => {
        if (res.status === 401) {
          await endSession()
          router.push("/login")
          router.refresh()
          return null
        }
        if (!res.ok) throw new Error(String(res.status))
        return (await res.json()) as VulnerabilityListResponse
      })
      .then((json) => {
        if (!cancelled && json) setResult({ key: queryKey, data: json })
      })
      .catch(() => {
        if (!cancelled) setResult({ key: queryKey, data: null })
      })
    return () => {
      cancelled = true
    }
  }, [queryKey, router, search, severity, ecosystem, kev, fix, followingOnly, tech, page, sort])

  const data = result.key === queryKey ? result.data : null

  const columns = useMemo(
    () =>
      col.columns([
        col.accessor("canonicalId", {
          header: "ID",
          cell: (c) => (
            <Link
              href={`/vulnerabilities/${c.row.original.id}`}
              className="font-mono text-[11px] hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
            >
              {c.getValue()}
            </Link>
          ),
        }),
        col.accessor("title", {
          header: "Title",
          cell: (c) => (
            <Link
              href={`/vulnerabilities/${c.row.original.id}`}
              className="block max-w-[28rem] truncate text-[13px] hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
            >
              {c.getValue()}
            </Link>
          ),
        }),
        col.accessor("severity", {
          header: "Severity",
          cell: (c) => <SeverityBadge severity={c.getValue()} />,
        }),
        col.accessor("cvssScore", {
          header: "CVSS",
          cell: (c) => (
            <span className="text-muted-foreground tabular-nums">
              {formatCvss(c.getValue())}
            </span>
          ),
        }),
        col.accessor("publishedAt", {
          header: "Published",
          cell: (c) => (
            <span className="text-muted-foreground text-xs tabular-nums">
              {formatRelativeTime(c.getValue())}
            </span>
          ),
        }),
        col.accessor("modifiedAt", {
          header: "Modified",
          cell: (c) => (
            <span className="text-muted-foreground text-xs tabular-nums">
              {formatRelativeTime(c.getValue())}
            </span>
          ),
        }),
        col.accessor("ecosystems", {
          header: "Ecosystems",
          cell: (c) => (
            <span className="text-muted-foreground text-xs">
              {c.getValue().join(", ") || "—"}
            </span>
          ),
        }),
        col.display({
          id: "affected",
          header: "Affected",
          cell: (c) => (
            <ProductBadge
              primaryVendor={c.row.original.primaryVendor}
              primaryProduct={c.row.original.primaryProduct}
              productType={c.row.original.productType}
              className="max-w-36"
            />
          ),
        }),
        col.accessor("isKnownExploited", {
          header: "KEV",
          cell: (c) =>
            c.getValue() ? (
              <Flame
                className="text-severity-high size-3.5"
                aria-label="Known exploited"
              />
            ) : (
              <span className="text-muted-foreground">—</span>
            ),
        }),
        col.accessor("hasFix", {
          header: "Fix",
          cell: (c) =>
            c.getValue() ? (
              <Wrench className="text-severity-low size-3.5" aria-label="Fix available" />
            ) : (
              <span className="text-muted-foreground">—</span>
            ),
        }),
      ]),
    []
  )

  const table = useTable({
    features,
    columns,
    data: data?.items ?? EMPTY_ITEMS,
  })

  const total = data?.total ?? 0
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const from = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const to = Math.min(total, page * PAGE_SIZE)

  function toggleSort(field: string) {
    replaceParams({ sort: sort === `-${field}` ? field : `-${field}` })
  }

  function sortIndicator(field: string) {
    if (sort === `-${field}`) return <ArrowDown className="size-3" aria-hidden />
    if (sort === field) return <ArrowUp className="size-3" aria-hidden />
    return null
  }

  const sortableFields = new Set(["publishedAt", "modifiedAt", "severity", "cvssScore"])

  return (
    <div className="flex flex-col gap-4">
      <div>
        <h1 className="text-base font-semibold">Vulnerabilities</h1>
        <p className="text-muted-foreground mt-0.5 text-xs">
          {tech
            ? `Advisories matching ${tech}.`
            : followingOnly
              ? "Advisories that match technologies you follow."
              : "Browse and filter the tracked vulnerability database."}
        </p>
      </div>

      <div
        className="flex flex-wrap items-center gap-2"
        role="search"
        aria-label="Vulnerability filters"
      >
        <Input
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search title or ID…"
          aria-label="Search vulnerabilities"
          className="w-56"
        />
        <Select
          value={severity || "all"}
          onValueChange={(v) => replaceParams({ severity: v === "all" ? "" : v })}
        >
          <SelectTrigger aria-label="Filter by severity" className="w-28">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {["Critical", "High", "Medium", "Low", "Unknown"].map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={ecosystem || "all"}
          onValueChange={(v) => replaceParams({ ecosystem: v === "all" ? "" : v })}
        >
          <SelectTrigger aria-label="Filter by ecosystem" className="w-28">
            <SelectValue placeholder="Ecosystem" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All ecosystems</SelectItem>
            {ECOSYSTEMS.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={kev || "all"}
          onValueChange={(v) => replaceParams({ kev: v === "all" ? "" : v })}
        >
          <SelectTrigger aria-label="Filter by known exploited status" className="w-28">
            <SelectValue placeholder="KEV" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">KEV: all</SelectItem>
            <SelectItem value="true">KEV only</SelectItem>
          </SelectContent>
        </Select>
        <Select
          value={fix || "all"}
          onValueChange={(v) => replaceParams({ fix: v === "all" ? "" : v })}
        >
          <SelectTrigger aria-label="Filter by fix availability" className="w-28">
            <SelectValue placeholder="Fix" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Fix: all</SelectItem>
            <SelectItem value="true">Has fix</SelectItem>
          </SelectContent>
        </Select>
        <Button
          type="button"
          size="sm"
          variant={followingOnly ? "default" : "outline"}
          aria-pressed={followingOnly}
          onClick={() =>
            replaceParams({
              following: followingOnly ? "" : "true",
              tech: "",
            })
          }
        >
          Following only
        </Button>
        {tech && (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => replaceParams({ tech: "" })}
          >
            Clear {tech}
          </Button>
        )}
      </div>

      {loading ? (
        <div className="flex flex-col gap-2" aria-busy="true" aria-label="Loading vulnerabilities">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-9 w-full" />
          ))}
        </div>
      ) : failed ? (
        <EmptyState
          title="Could not load vulnerabilities"
          description="The API may be unavailable. Try again in a moment."
        />
      ) : total === 0 ? (
        <EmptyState
          title="No vulnerabilities found"
          description={
            tech || followingOnly
              ? "Nothing in the current window matches this follow filter. Try a wider date range, or follow a more specific package."
              : "No vulnerabilities match these filters. Adjust or clear the filters, or wait for the next ingestion sync."
          }
        />
      ) : (
        <div className="border-line rounded-md border">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((hg) => (
                <TableRow key={hg.id}>
                  {hg.headers.map((header) => {
                    const field = header.column.id
                    const sortable = sortableFields.has(field)
                    return (
                      <TableHead key={header.id}>
                        {sortable ? (
                          <button
                            type="button"
                            onClick={() => toggleSort(field)}
                            className="inline-flex items-center gap-1 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
                            aria-label={`Sort by ${field}`}
                          >
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {sortIndicator(field)}
                          </button>
                        ) : (
                          flexRender(header.column.columnDef.header, header.getContext())
                        )}
                      </TableHead>
                    )
                  })}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <div className="flex items-center justify-between gap-2">
        <p className="text-muted-foreground text-xs tabular-nums">
          Showing {from}–{to} of {total}
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page <= 1 || loading}
            onClick={() => replaceParams({ page: String(page - 1) })}
          >
            Prev
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={page >= pageCount || loading}
            onClick={() => replaceParams({ page: String(page + 1) })}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  )
}
