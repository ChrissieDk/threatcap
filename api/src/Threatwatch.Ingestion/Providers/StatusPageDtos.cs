using System.Text.Json.Serialization;

namespace Threatwatch.Ingestion.Providers;

public sealed class StatusPageFeedResponse
{
    [JsonPropertyName("page")] public StatusPagePage Page { get; set; } = new();
    [JsonPropertyName("incidents")] public List<StatusPageIncident> Incidents { get; set; } = [];
}

public sealed class StatusPagePage
{
    [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("url")] public string Url { get; set; } = string.Empty;
    [JsonPropertyName("updated_at")] public string? UpdatedAt { get; set; }
}

public sealed class StatusPageIncident
{
    [JsonPropertyName("id")] public string Id { get; set; } = string.Empty;
    [JsonPropertyName("name")] public string Name { get; set; } = string.Empty;
    [JsonPropertyName("status")] public string Status { get; set; } = string.Empty;
    [JsonPropertyName("impact")] public string Impact { get; set; } = string.Empty;
    [JsonPropertyName("shortlink")] public string? Shortlink { get; set; }
    [JsonPropertyName("created_at")] public string? CreatedAt { get; set; }
    [JsonPropertyName("started_at")] public string? StartedAt { get; set; }
    [JsonPropertyName("updated_at")] public string? UpdatedAt { get; set; }
    [JsonPropertyName("resolved_at")] public string? ResolvedAt { get; set; }
    [JsonPropertyName("incident_updates")] public List<StatusPageIncidentUpdate> IncidentUpdates { get; set; } = [];
}

public sealed class StatusPageIncidentUpdate
{
    [JsonPropertyName("status")] public string Status { get; set; } = string.Empty;
    [JsonPropertyName("body")] public string Body { get; set; } = string.Empty;
    [JsonPropertyName("created_at")] public string? CreatedAt { get; set; }
}
