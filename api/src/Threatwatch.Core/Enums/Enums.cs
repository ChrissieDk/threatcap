namespace Threatwatch.Core.Enums;

public enum Severity
{
    Unknown = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

public enum AliasType
{
    Other = 0,
    Cve = 1,
    Ghsa = 2,
}

public enum Ecosystem
{
    Other = 0,
    Npm = 1,
    NuGet = 2,
    PyPI = 3,
    Maven = 4,
    Cargo = 5,
    Go = 6,
    GithubActions = 7,
    Linux = 8,
}

public enum TechnologyType
{
    Language = 0,
    Framework = 1,
    Runtime = 2,
    Package = 3,
    Ecosystem = 4,
    Infrastructure = 5,
}

public enum SourceType
{
    Osv = 0,
    CisaKev = 1,
    Nvd = 2,
    GitHubAdvisory = 3,
    Reddit = 4,
    StatusPage = 5,
}

public enum IncidentType
{
    Outage = 0,
    ServiceDegradation = 1,
    ExploitationReported = 2,
    SecurityIncident = 3,
    SuspectedSecurityIncident = 4,
}

public enum IncidentStatus
{
    Investigating = 0,
    Identified = 1,
    Monitoring = 2,
    Resolved = 3,
}

public enum VulnerabilityEventType
{
    Published = 0,
    SeverityChanged = 1,
    KnownExploitedAdded = 2,
    FixAvailable = 3,
    AdvisoryUpdated = 4,
}

public enum ProductType
{
    Library = 0,
    App = 1,
    Os = 2,
    Service = 3,
    Other = 4,
}

public enum IngestionSource
{
    Osv = 0,
    CisaKev = 1,
    Epss = 2,
    StatusPage = 3,
}
