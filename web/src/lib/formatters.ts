import type { Severity } from "@/lib/api/types";

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Never";
  const diffMs = Date.now() - date.getTime();
  const past = diffMs >= 0;
  const abs = Math.abs(diffMs);
  const minutes = Math.floor(abs / 60_000);
  if (minutes < 1) return past ? "just now" : "in <1 minute";
  if (minutes < 60) return relativePhrase(minutes, "minute", past);
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return relativePhrase(hours, "hour", past);
  const days = Math.floor(hours / 24);
  if (days < 30) return relativePhrase(days, "day", past);
  const months = Math.floor(days / 30);
  if (months < 12) return relativePhrase(months, "month", past);
  return relativePhrase(Math.floor(months / 12), "year", past);
}

export type RelativeAge = "fresh" | "recent" | "older" | "unknown";

/** Visual age for list timestamps: under a day, under a week, or older. */
export function relativeAge(iso: string | null | undefined): RelativeAge {
  if (!iso) return "unknown";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "unknown";
  const hours = Math.abs(Date.now() - date.getTime()) / 3_600_000;
  if (hours < 24) return "fresh";
  if (hours < 24 * 7) return "recent";
  return "older";
}

function relativePhrase(count: number, unit: string, past: boolean): string {
  const amount = `${count} ${count === 1 ? unit : `${unit}s`}`;
  return past ? `${amount} ago` : `in ${amount}`;
}

export function formatUtcDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }) + " UTC";
}

export function formatCvss(score: number | null | undefined): string {
  if (score === null || score === undefined) return "—";
  return score.toFixed(1);
}

export type SeverityMeta = {
  label: string;
  badgeClass: string;
  dotClass: string;
};

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  Critical: {
    label: "Critical",
    badgeClass: "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
    dotClass: "bg-severity-critical",
  },
  High: {
    label: "High",
    badgeClass: "border-severity-high/30 bg-severity-high/10 text-severity-high",
    dotClass: "bg-severity-high",
  },
  Medium: {
    label: "Medium",
    badgeClass: "border-severity-medium/30 bg-severity-medium/10 text-severity-medium",
    dotClass: "bg-severity-medium",
  },
  Low: {
    label: "Low",
    badgeClass: "border-severity-low/30 bg-severity-low/10 text-severity-low",
    dotClass: "bg-severity-low",
  },
  Unknown: {
    label: "Unknown",
    badgeClass: "border-line-strong bg-surface-2 text-muted-foreground",
    dotClass: "bg-severity-unknown",
  },
};
