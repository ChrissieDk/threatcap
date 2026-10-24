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
