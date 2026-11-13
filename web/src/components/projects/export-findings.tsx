"use client"

import { Download } from "lucide-react"
import { Button } from "@/components/ui/button"
import { toCsv } from "@/lib/csv"
import type { ProjectFinding } from "@/lib/api/types"

const HEADER = [
  "Advisory", "Title", "Severity", "CVSS", "Priority", "Actively exploited",
  "Package", "Version", "Version basis", "Fixed in", "Direct", "Dev only", "Triage", "Snoozed until",
]

/** Download a project's findings as a CSV file. Built in the browser from the data already on the page. */
export function ExportFindings({ projectName, findings }: { projectName: string; findings: ProjectFinding[] }) {
  function download() {
    const csv = toCsv([
      HEADER,
      ...findings.map((f) => [
        f.canonicalId, f.title, f.severity, f.cvssScore, f.priorityScore === null ? null : f.priorityScore.toFixed(1),
        f.isKnownExploited, f.package, f.version, f.versionKind === "Declared" ? "declared range (lowest)" : "exact",
        f.fixedIn, f.isDirect, f.isDev, f.triage, f.snoozedUntil,
      ]),
    ])
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }))
    const link = document.createElement("a")
    link.href = url
    link.download = `${projectName.replace(/[^\w.-]+/g, "-").slice(0, 60) || "project"}-findings.csv`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Button type="button" size="sm" variant="outline" onClick={download} disabled={findings.length === 0}>
      <Download aria-hidden /> Export CSV
    </Button>
  )
}
