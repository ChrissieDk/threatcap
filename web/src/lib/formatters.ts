import type { Severity } from "@/lib/api/types";

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "Never";
  const diffMs = Date.now() - date.getTime();
  const abs = Math.abs(diffMs);
  const suffix = diffMs >= 0 ? "ago" : "from now";
  const minutes = Math.floor(abs / 60_000);
  if (minutes < 1) return diffMs >= 0 ? "just now" : "in <1m";
  if (minutes < 60) return `${minutes}m ${suffix}`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ${suffix}`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ${suffix}`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ${suffix}`;
  return `${Math.floor(months / 12)}y ${suffix}`;
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
