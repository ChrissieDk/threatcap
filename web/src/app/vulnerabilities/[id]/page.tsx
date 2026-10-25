import { notFound, redirect } from "next/navigation"
import Link from "next/link"
import { ExternalLink, Flame } from "lucide-react"
import { ApiError, apiGet } from "@/lib/api/client"
import type { Technology, VulnerabilityDetail } from "@/lib/api/types"
import { catalogMatchForPackage } from "@/lib/tech-match"
import { FollowButton } from "@/components/technologies/follow-button"
import { SeverityBadge } from "@/components/severity-badge"
import { ProductBadge } from "@/components/product-badge"
import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatUtcDate } from "@/lib/formatters"
import { RelativeTime } from "@/components/relative-time"

const EVENT_LABELS: Record<VulnerabilityDetail["events"][number]["eventType"], string> = {
  Published: "Published",
  SeverityChanged: "Severity changed",
  KnownExploitedAdded: "Added to CISA KEV",
  FixAvailable: "Fix available",
  AdvisoryUpdated: "Advisory updated",
}

function ordinal(n: number): string {
  const s = ["th", "st", "nd", "rd"]
  const v = n % 100
  return `${n}${s[(v - 20) % 10] || s[v] || s[0]}`
}

export default async function VulnerabilityDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  let vuln: VulnerabilityDetail
  try {
    vuln = await apiGet<VulnerabilityDetail>(`/api/v1/vulnerabilities/${id}`)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) notFound()
    if (err instanceof ApiError && err.status === 401) redirect("/login")
    throw err
  }

  let catalog: Technology[] = []
  try {
    catalog = await apiGet<Technology[]>("/api/v1/technologies")
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) redirect("/login")
  }

  const sortedEvents = [...vuln.events].sort((a, b) =>
    b.eventAt.localeCompare(a.eventAt)
  )

  return (
    <div className="flex flex-col gap-6">
      <div>
        <p className="text-muted-foreground font-mono text-xs">
          <Link
            href="/vulnerabilities"
            className="hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
          >
            Vulnerabilities
          </Link>{" "}
          / {vuln.canonicalId}
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="font-mono text-lg font-semibold break-all">
            {vuln.canonicalId}
          </h1>
          <SeverityBadge severity={vuln.severity} />
          {vuln.isWithdrawn && <Badge variant="secondary">Withdrawn</Badge>}
          {(vuln.primaryVendor || vuln.primaryProduct) && (
            <ProductBadge
              primaryVendor={vuln.primaryVendor}
              primaryProduct={vuln.primaryProduct}
              productType={vuln.productType}
            />
          )}
          <span className="text-muted-foreground text-xs">
            {vuln.cvssScore !== null
              ? `CVSS ${vuln.cvssScore.toFixed(1)}${
                  vuln.cvssSource ? ` (${vuln.cvssSource})` : ""
                }`
              : "No CVSS score"}
            {vuln.epssPercentile !== null &&
              ` · EPSS: ${ordinal(Math.round(vuln.epssPercentile * 100))} percentile`}
          </span>
          {vuln.priorityScore !== null && (
            <Badge variant="secondary" title="Priority score (CVSS × EPSS/KEV weighting)">
              Priority {vuln.priorityScore.toFixed(1)}
            </Badge>
          )}
        </div>
        <p className="mt-1.5 text-sm">{vuln.title}</p>
      </div>

      {vuln.isKnownExploited && (
        <div
          role="alert"
          className="border-severity-high/40 bg-severity-high/10 flex items-start gap-3 rounded-md border p-3"
        >
          <Flame className="text-severity-high mt-0.5 size-4 shrink-0" aria-hidden />
          <div>
            <p className="text-severity-high text-[13px] font-medium">
              Listed in CISA Known Exploited Vulnerabilities
            </p>
            <a
              href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
              target="_blank"
              rel="noreferrer"
              className="text-muted-foreground hover:text-foreground text-xs underline underline-offset-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
            >
              View the CISA KEV catalog
            </a>
          </div>
        </div>
      )}

      <dl className="border-line grid grid-cols-2 gap-px overflow-hidden rounded-md border sm:grid-cols-4">
        {[
          ["Published", vuln.publishedAt],
          ["Last modified", vuln.modifiedAt],
        ].map(([label, value]) => (
          <div key={label} className="bg-surface px-3 py-2.5">
            <dt className="text-muted-foreground text-[11px] uppercase">{label}</dt>
            <dd className="mt-1 flex flex-wrap items-center gap-1.5 text-xs tabular-nums">
              <span>{formatUtcDate(value)}</span>
              <RelativeTime iso={value} />
            </dd>
          </div>
        ))}
        <div className="bg-surface px-3 py-2.5">
          <dt className="text-muted-foreground text-[11px] uppercase">CVSS vector</dt>
          <dd className="text-muted-foreground mt-0.5 font-mono text-[11px] break-all">
            {vuln.cvssVector ?? "—"}
          </dd>
        </div>
        <div className="bg-surface px-3 py-2.5">
          <dt className="text-muted-foreground text-[11px] uppercase">Sources</dt>
          <dd className="mt-0.5 text-xs">{vuln.references.length}</dd>
        </div>
      </dl>

      {vuln.description && (
        <section aria-label="Description">
          <h2 className="text-sm font-medium">Description</h2>
          <p className="text-muted-foreground mt-2 max-w-3xl text-[13px] leading-relaxed whitespace-pre-wrap">
            {vuln.description}
          </p>
        </section>
      )}

      {vuln.aliases.length > 0 && (
        <section aria-label="Aliases">
          <h2 className="text-sm font-medium">Aliases</h2>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {vuln.aliases.map((a) => (
              <li key={a.alias}>
                <Badge variant="secondary" className="font-mono">
                  {a.alias}
                </Badge>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section aria-label="Affected packages">
        <h2 className="text-sm font-medium">Affected packages</h2>
        {vuln.affectedPackages.length === 0 ? (
          <p className="text-muted-foreground mt-2 text-xs">
            No affected package information recorded.
          </p>
        ) : (
          <div className="border-line mt-2 rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Ecosystem</TableHead>
                  <TableHead>Package</TableHead>
                  <TableHead>Affected ranges</TableHead>
                  <TableHead>Fixed versions</TableHead>
                  <TableHead className="text-right">
                    <span className="sr-only">Follow</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vuln.affectedPackages.map((p, i) => {
                  const match = catalogMatchForPackage(
                    catalog,
                    p.ecosystem,
                    p.packageName,
                    p.displayName
                  )
                  return (
                    <TableRow key={`${p.ecosystem}-${p.packageName}-${i}`}>
                      <TableCell className="text-muted-foreground">{p.ecosystem}</TableCell>
                      <TableCell className="font-mono text-[11px]">
                        {p.packageUrl ? (
                          <a
                            href={p.packageUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
                          >
                            {p.displayName}
                          </a>
                        ) : (
                          p.displayName
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-[11px]">
                        {p.affectedRanges ?? "—"}
                      </TableCell>
                      <TableCell className="font-mono text-[11px]">
                        {p.fixedVersions?.join(", ") || "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        {match ? (
                          <FollowButton
                            slug={match.slug}
                            following={match.following}
                            name={match.name}
                          />
                        ) : (
                          <FollowButton
                            following={false}
                            ecosystem={p.ecosystem}
                            packageName={p.packageName}
                            name={p.displayName}
                          />
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      <section aria-label="References">
        <h2 className="text-sm font-medium">References</h2>
        {vuln.references.length === 0 ? (
          <p className="text-muted-foreground mt-2 text-xs">No references recorded.</p>
        ) : (
          <ul className="border-line mt-2 divide-y divide-line rounded-md border">
            {vuln.references.map((r, i) => (
              <li key={`${r.url}-${i}`} className="flex items-center gap-2.5 px-3 py-2">
                <Badge variant="secondary">{r.sourceType}</Badge>
                <a
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  className="truncate text-xs hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-sm"
                >
                  {r.externalId || r.url}
                </a>
                <ExternalLink
                  className="text-muted-foreground size-3 shrink-0"
                  aria-hidden
                />
                {r.publishedAt && (
                  <RelativeTime iso={r.publishedAt} className="ml-auto" />
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-label="Event timeline">
        <h2 className="text-sm font-medium">Timeline</h2>
        {sortedEvents.length === 0 ? (
          <p className="text-muted-foreground mt-2 text-xs">No events recorded.</p>
        ) : (
          <ol className="relative mt-3 ml-1.5 border-l border-line pl-5">
            {sortedEvents.map((e, i) => (
              <li key={`${e.eventAt}-${i}`} className="relative pb-4 last:pb-0">
                <span
                  className="bg-primary absolute top-1 -left-[23px] size-2 rounded-full"
                  aria-hidden
                />
                <p className="text-[13px] font-medium">{EVENT_LABELS[e.eventType]}</p>
                <p className="mt-1 flex flex-wrap items-center gap-1.5 text-xs tabular-nums">
                  <time dateTime={e.eventAt} className="text-muted-foreground">
                    {formatUtcDate(e.eventAt)}
                  </time>
                  <RelativeTime iso={e.eventAt} />
                </p>
                {e.details && (
                  <p className="text-muted-foreground mt-1 text-xs">{e.details}</p>
                )}
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  )
}
