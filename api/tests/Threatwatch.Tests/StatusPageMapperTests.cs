using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class StatusPageMapperTests
{
    [Theory]
    [InlineData("investigating", false, IncidentStatus.Investigating)]
    [InlineData("identified", false, IncidentStatus.Identified)]
    [InlineData("monitoring", false, IncidentStatus.Monitoring)]
    [InlineData("resolved", false, IncidentStatus.Resolved)]
    [InlineData("postmortem", false, IncidentStatus.Resolved)]
    [InlineData("unknown", true, IncidentStatus.Resolved)]
    [InlineData("unknown", false, IncidentStatus.Investigating)]
    public void MapStatusCoversStatuspageStates(string status, bool resolved, IncidentStatus expected)
    {
        Assert.Equal(expected, StatusPageMapper.MapStatus(status, resolved));
    }

    [Fact]
    public void MapTypeTreatsMajorImpactAsOutage()
    {
        Assert.Equal(IncidentType.Outage, StatusPageMapper.MapType("major", "Registry down", null));
        Assert.Equal(IncidentType.ServiceDegradation, StatusPageMapper.MapType("minor", "Elevated errors", null));
    }

    [Fact]
    public void MapTypeDetectsSecurityWording()
    {
        Assert.Equal(
            IncidentType.SecurityIncident,
            StatusPageMapper.MapType("minor", "Security incident on the API", null));
    }

    [Fact]
    public void IncidentUrlFallsBackToPagePathWhenShortlinkMissing()
    {
        var url = StatusPageMapper.IncidentUrl(
            new StatusPageIncident { Id = "abc123" },
            new StatusPagePage { Url = "https://www.dockerstatus.com/" });

        Assert.Equal("https://www.dockerstatus.com/incidents/abc123", url);
    }
}
