export type SyncSource = "Osv" | "CisaKev" | "Epss" | "StatusPage" | "Nvd" | "GitHubAdvisory";

export type IngestionSyncStatus = {
  running: boolean;
  currentSource?: string | null;
  startedAt?: string | null;
  started?: boolean;
};

export type DashboardSummary = {
  newVulnerabilities: number;
  criticalHigh: number;
  kevAdded: number;
  activeIncidents: number;
  followedCount: number;
  followedTopicsWithActivity: number;
  lastSyncs: Array<{
    source: SyncSource;
    lastSuccessfulSyncAt: string | null;
    lastError: string | null;
  }>;
};

export type DailyMetric = "disclosures" | "updates" | "kev" | "incidents";

export type DailyPoint = {
  date: string; // yyyy-MM-dd UTC
  count: number;
};

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Unknown";

export type ProductType = "Library" | "App" | "Os" | "Service" | "Other";

export type VulnerabilityListItem = {
  id: string; // uuid
  canonicalId: string;
  title: string;
  severity: Severity;
  cvssScore: number | null;
  publishedAt: string;
  modifiedAt: string;
  isKnownExploited: boolean;
  hasFix: boolean;
  ecosystems: string[];
  sources: string[];
  primaryVendor: string | null;
  primaryProduct: string | null;
  productType: ProductType | null;
  epssScore: number | null;
  epssPercentile: number | null;
  priorityScore: number | null;
};

export type VulnerabilityListResponse = {
  items: VulnerabilityListItem[];
  total: number;
  page: number;
  pageSize: number;
};

export type VulnerabilityDetail = {
  id: string;
  canonicalId: string;
  title: string;
  description: string | null;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  cvssSource: string | null;
  primaryVendor: string | null;
  primaryProduct: string | null;
  productType: ProductType | null;
  epssScore: number | null;
  epssPercentile: number | null;
  priorityScore: number | null;
  publishedAt: string;
  modifiedAt: string;
  isKnownExploited: boolean;
  isWithdrawn: boolean;
  aliases: Array<{ alias: string; aliasType: "Cve" | "Ghsa" | "Other" }>;
  affectedPackages: Array<{
    ecosystem: string;
    packageName: string;
    displayName: string;
    affectedRanges: string | null;
    fixedVersions: string[] | null;
    packageUrl: string | null;
    provenance: string | null;
  }>;
  references: Array<{
    sourceType: string;
    url: string;
    externalId: string;
    publishedAt: string | null;
  }>;
  events: Array<{
    eventType:
      | "Published"
      | "SeverityChanged"
      | "KnownExploitedAdded"
      | "FixAvailable"
      | "AdvisoryUpdated";
    eventAt: string;
    details: string | null;
  }>;
};

export type Technology = {
  id: string;
  slug: string;
  name: string;
  type: string;
  ecosystem: string | null;
  aliases: string[];
  following: boolean;
};

export type FollowedTechnology = {
  id: string;
  slug: string;
  name: string;
  type: string;
  ecosystem: string | null;
  ecosystemWide: boolean;
  followedAt: string;
  recentActivityCount: number;
  kevCount: number;
  criticalHighCount: number;
  lastActivityAt: string | null;
};

export type TechnologyDetail = Technology;

export type ActNowItem = {
  id: string;
  canonicalId: string;
  title: string;
  severity: Severity;
  priorityScore: number | null;
  primaryVendor: string | null;
  primaryProduct: string | null;
  productType: ProductType | null;
  epssScore: number | null;
  epssPercentile: number | null;
  isKnownExploited: boolean;
  publishedAt: string;
};

export type IncidentStatus =
  | "Investigating"
  | "Identified"
  | "Monitoring"
  | "Resolved"

export type IncidentType =
  | "Outage"
  | "ServiceDegradation"
  | "ExploitationReported"
  | "SecurityIncident"
  | "SuspectedSecurityIncident"

export type SecurityIncidentItem = {
  id: string
  title: string
  description: string | null
  type: IncidentType
  status: IncidentStatus
  vendorSlug: string
  vendorName: string
  ecosystem: string | null
  url: string | null
  startedAt: string
  resolvedAt: string | null
  updatedAt: string
}

export type ProviderHealth = {
  source: string;
  lastSuccessfulSyncAt: string | null;
  lastAttemptedSyncAt: string | null;
  lastError: string | null;
  lastDurationMs: number | null;
};
