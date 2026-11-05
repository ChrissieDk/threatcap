using Microsoft.AspNetCore.Identity;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Entities;

public class Vulnerability
{
    public Guid Id { get; set; }
    public required string CanonicalId { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public Severity Severity { get; set; } = Severity.Unknown;
    public decimal? CvssScore { get; set; }
    public string? CvssVector { get; set; }
    public string? CvssSource { get; set; }
    public DateTimeOffset PublishedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
    public bool IsKnownExploited { get; set; }
    public bool IsWithdrawn { get; set; }
    public string? PrimaryVendor { get; set; }
    public string? PrimaryProduct { get; set; }
    public ProductType? ProductType { get; set; }
    public double? EpssScore { get; set; }
    public double? EpssPercentile { get; set; }
    public double? PriorityScore { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public ICollection<VulnerabilityAlias> Aliases { get; set; } = new List<VulnerabilityAlias>();
    public ICollection<AffectedPackage> AffectedPackages { get; set; } = new List<AffectedPackage>();
    public ICollection<SourceReference> SourceReferences { get; set; } = new List<SourceReference>();
    public ICollection<VulnerabilityEvent> Events { get; set; } = new List<VulnerabilityEvent>();
}

public class VulnerabilityAlias
{
    public Guid Id { get; set; }
    public Guid VulnerabilityId { get; set; }
    public required string Alias { get; set; }
    public AliasType AliasType { get; set; }

    public Vulnerability Vulnerability { get; set; } = null!;
}

public class AffectedPackage
{
    public Guid Id { get; set; }
    public Guid VulnerabilityId { get; set; }
    public Ecosystem Ecosystem { get; set; }
    public required string PackageName { get; set; }
    public required string DisplayName { get; set; }
    public string AffectedRanges { get; set; } = "[]";
    public string[] FixedVersions { get; set; } = [];
    public string? PackageUrl { get; set; }
    public string Provenance { get; set; } = string.Empty;

    public Vulnerability Vulnerability { get; set; } = null!;
}

public class Technology
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public required string Slug { get; set; }
    public TechnologyType Type { get; set; }
    public Ecosystem? Ecosystem { get; set; }
    public string[] Aliases { get; set; } = [];
    public string? MatchingRules { get; set; }
}

public class UserAccount : IdentityUser<Guid>
{
    public string? ExternalId { get; set; }
    public required string DisplayName { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    /// <summary>Read cursor for in-app notifications; null means "nothing marked read yet".</summary>
    public DateTimeOffset? LastNotificationsReadAt { get; set; }

    public ICollection<UserFollow> Follows { get; set; } = new List<UserFollow>();
}

public class UserFollow
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Guid TechnologyId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }

    public UserAccount User { get; set; } = null!;
    public Technology Technology { get; set; } = null!;
}

public class SourceReference
{
    public Guid Id { get; set; }
    public SourceType SourceType { get; set; }
    public required string ExternalId { get; set; }
    public string? Url { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public DateTimeOffset? SourceModifiedAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; }
    public Guid? VulnerabilityId { get; set; }

    public Vulnerability? Vulnerability { get; set; }
}

public class SecurityIncident
{
    public Guid Id { get; set; }
    public IncidentType Type { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public IncidentStatus Status { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? ResolvedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public SourceType SourceType { get; set; } = SourceType.StatusPage;
    public required string ExternalId { get; set; }
    public string? Url { get; set; }
    public required string VendorSlug { get; set; }
    public required string VendorName { get; set; }
    public Ecosystem? Ecosystem { get; set; }
}

public class VulnerabilityEvent
{
    public Guid Id { get; set; }
    public Guid VulnerabilityId { get; set; }
    public VulnerabilityEventType EventType { get; set; }
    public DateTimeOffset EventAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; }
    public string? Details { get; set; }

    public Vulnerability Vulnerability { get; set; } = null!;
}

public class IngestionState
{
    public Guid Id { get; set; }
    public IngestionSource Source { get; set; }
    public DateTimeOffset? LastSuccessfulSyncAt { get; set; }
    public DateTimeOffset? LastAttemptedSyncAt { get; set; }
    public string? Watermark { get; set; }
    public string? LastError { get; set; }
    public long? LastDurationMs { get; set; }
}

/// <summary>Per-user alert rules. One row per user; absent means alerts are off.</summary>
public class AlertPreference
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public Severity MinSeverity { get; set; } = Severity.High;
    public bool AlwaysAlertKnownExploited { get; set; } = true;
    public double? MinEpss { get; set; }
    public bool IncludeIncidents { get; set; }
    public AlertDeliveryMode Mode { get; set; } = AlertDeliveryMode.Instant;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public UserAccount User { get; set; } = null!;
}

public class AlertChannel
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public AlertChannelType Type { get; set; }
    public required string Label { get; set; }

    /// <summary>
    /// Data-protection-encrypted destination (webhook URL or ntfy topic URL). Null for
    /// email, which always goes to the account address. Never returned by the API.
    /// </summary>
    public string? ProtectedTarget { get; set; }

    /// <summary>Non-secret display hint such as the target host.</summary>
    public string? TargetHint { get; set; }
    public bool IsEnabled { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? LastDeliveredAt { get; set; }
    public DateTimeOffset? LastDigestAt { get; set; }
    public string? LastError { get; set; }
    public int ConsecutiveFailures { get; set; }

    public UserAccount User { get; set; } = null!;
}

/// <summary>
/// One row per (channel, item). The unique key makes enqueueing idempotent, so
/// reprocessing source data can never alert twice for the same item.
/// </summary>
public class AlertDelivery
{
    public Guid Id { get; set; }
    public Guid ChannelId { get; set; }
    public AlertItemKind ItemKind { get; set; }
    public Guid ItemId { get; set; }
    public required string Title { get; set; }
    public string? Summary { get; set; }
    public string? Url { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset? SentAt { get; set; }
    public DateTimeOffset? AbandonedAt { get; set; }
    public int Attempts { get; set; }
    public DateTimeOffset? NextAttemptAt { get; set; }

    public AlertChannel Channel { get; set; } = null!;
}

/// <summary>Small encrypted key/value store for server-generated secrets (e.g. VAPID keys).</summary>
public class AppSetting
{
    public required string Key { get; set; }
    public required string ProtectedValue { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>A user's software project, described by uploaded dependency files (the files themselves are not kept).</summary>
public class Project
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public required string Name { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public UserAccount User { get; set; } = null!;
    public ICollection<ProjectDependency> Dependencies { get; set; } = new List<ProjectDependency>();
}

/// <summary>One dependency as read from one source file; merged across files when read.</summary>
public class ProjectDependency
{
    public Guid Id { get; set; }
    public Guid ProjectId { get; set; }
    public required string SourceFile { get; set; }
    public Ecosystem Ecosystem { get; set; }
    public required string Name { get; set; }
    public required string DisplayName { get; set; }
    public string? Version { get; set; }
    public Threatwatch.Core.Projects.VersionKind VersionKind { get; set; }
    public bool IsDev { get; set; }
    public bool IsDirect { get; set; }

    public Project Project { get; set; } = null!;
}
