import { describe, expect, it } from "vitest"
import {
  SEVERITY_META,
  formatCvss,
  formatRelativeTime,
  formatUtcDate,
} from "@/lib/formatters"
import type { Severity } from "@/lib/api/types"

describe("formatRelativeTime", () => {
  it("returns Never for null or invalid input", () => {
    expect(formatRelativeTime(null)).toBe("Never")
    expect(formatRelativeTime(undefined)).toBe("Never")
    expect(formatRelativeTime("not-a-date")).toBe("Never")
  })

  it("formats minutes, hours, and days ago", () => {
    const now = Date.now()
    expect(formatRelativeTime(new Date(now - 5 * 60_000).toISOString())).toBe("5m ago")
    expect(formatRelativeTime(new Date(now - 3 * 3_600_000).toISOString())).toBe("3h ago")
    expect(formatRelativeTime(new Date(now - 2 * 86_400_000).toISOString())).toBe("2d ago")
  })

  it("formats future times", () => {
    const future = new Date(Date.now() + 2 * 60 * 60_000).toISOString()
    expect(formatRelativeTime(future)).toBe("2h from now")
  })
})

describe("formatUtcDate", () => {
  it("returns em dash for missing input", () => {
    expect(formatUtcDate(null)).toBe("—")
    expect(formatUtcDate(undefined)).toBe("—")
  })

  it("appends UTC and formats the date", () => {
    const out = formatUtcDate("2026-10-20T12:00:00Z")
    expect(out).toContain("UTC")
    expect(out).toContain("Oct")
  })
})

describe("formatCvss", () => {
  it("formats scores to one decimal", () => {
    expect(formatCvss(9.8)).toBe("9.8")
    expect(formatCvss(7)).toBe("7.0")
  })
  it("returns em dash when missing", () => {
    expect(formatCvss(null)).toBe("—")
    expect(formatCvss(undefined)).toBe("—")
  })
})

describe("SEVERITY_META", () => {
  it("has an entry for every severity", () => {
    const severities: Severity[] = ["Critical", "High", "Medium", "Low", "Unknown"]
    for (const s of severities) {
      expect(SEVERITY_META[s]).toBeDefined()
      expect(SEVERITY_META[s].label).toBe(s)
      expect(SEVERITY_META[s].badgeClass.length).toBeGreaterThan(0)
    }
  })
})
