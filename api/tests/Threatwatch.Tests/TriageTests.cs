using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Projects;

namespace Threatwatch.Tests;

public class TriageTests : IDisposable
{
    private const string Ranges = """[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]""";

    private readonly ThreatwatchDbContext _db;
    private readonly ProjectService _projects;
    private readonly TriageService _triage;
    private readonly Guid _userId = Guid.NewGuid();
    private readonly Guid _otherUserId = Guid.NewGuid();
    private readonly Guid _vulnId = Guid.NewGuid();
    private Guid _projectId;

    public TriageTests()
    {
        _db = new ThreatwatchDbContext(new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        _projects = new ProjectService(_db);
        _triage = new TriageService(_db);
        foreach (var id in new[] { _userId, _otherUserId })
        {
            _db.Users.Add(new UserAccount
            {
                Id = id, Email = $"{id}@example.com", UserName = $"{id}@example.com",
                DisplayName = "Dev", CreatedAt = DateTimeOffset.UtcNow,
            });
        }

        var v = new Vulnerability
        {
            Id = _vulnId, CanonicalId = "GHSA-lodash", Title = "lodash", Severity = Severity.Critical, IsKnownExploited = true,
            PublishedAt = DateTimeOffset.UtcNow.AddHours(-1), ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        };
        v.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(), VulnerabilityId = v.Id, Ecosystem = Ecosystem.Npm,
            PackageName = "lodash", DisplayName = "lodash", AffectedRanges = Ranges, FixedVersions = ["4.17.21"],
        });
        _db.Vulnerabilities.Add(v);
        _db.SaveChanges();

        var (created, _) = _projects.CreateAsync(_userId, "web", [
            new ProjectFileInput("package-lock.json", """{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"""),
        ], default).GetAwaiter().GetResult();
        _projectId = created!.Id;
    }

    public void Dispose() => _db.Dispose();

    [Theory]
    [InlineData(TriageStatus.Acknowledged)]
    [InlineData(TriageStatus.Ignored)]
    public async Task Triaged_findings_leave_the_counts_but_stay_listed(TriageStatus status)
    {
        Assert.Equal((null, true), await _triage.SetAsync(_userId, _projectId, _vulnId, status, null, default));

        var detail = (await _projects.GetAsync(_userId, _projectId, default))!;
        Assert.Equal(status, Assert.Single(detail.Findings).Triage);
        Assert.Equal((0, 0, 0), (detail.Summary.FindingCount, detail.Summary.CriticalHighCount, detail.Summary.KnownExploitedCount));

        Assert.Equal(0, (await _projects.OverviewAsync(_userId, 5, default)).FindingCount);
        Assert.Equal(0, Assert.Single(await _projects.ListAsync(_userId, default)).FindingCount);
    }

    [Fact]
    public async Task Reopening_restores_the_finding()
    {
        await _triage.SetAsync(_userId, _projectId, _vulnId, TriageStatus.Ignored, null, default);
        Assert.True(await _triage.ClearAsync(_userId, _projectId, _vulnId, default));

        var detail = (await _projects.GetAsync(_userId, _projectId, default))!;
        Assert.Null(Assert.Single(detail.Findings).Triage);
        Assert.Equal(1, detail.Summary.FindingCount);
    }

    [Fact]
    public async Task Setting_twice_updates_the_one_row()
    {
        await _triage.SetAsync(_userId, _projectId, _vulnId, TriageStatus.Acknowledged, null, default);
        await _triage.SetAsync(_userId, _projectId, _vulnId, TriageStatus.Ignored, null, default);

        Assert.Equal(TriageStatus.Ignored, (await _db.FindingTriages.SingleAsync()).Status);
    }

    [Fact]
    public async Task A_snooze_applies_until_it_expires()
    {
        await _triage.SetAsync(_userId, _projectId, _vulnId, TriageStatus.Snoozed, 7, default);
        Assert.Equal(0, (await _projects.GetAsync(_userId, _projectId, default))!.Summary.FindingCount);

        var row = await _db.FindingTriages.SingleAsync();
        row.SnoozedUntil = DateTimeOffset.UtcNow.AddMinutes(-1);
        await _db.SaveChangesAsync();

        var detail = (await _projects.GetAsync(_userId, _projectId, default))!;
        Assert.Null(Assert.Single(detail.Findings).Triage);
        Assert.Equal(1, detail.Summary.FindingCount);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    [InlineData(366)]
    public async Task A_snooze_needs_a_sensible_length(int? days)
    {
        var (error, found) = await _triage.SetAsync(_userId, _projectId, _vulnId, TriageStatus.Snoozed, days, default);
        Assert.True(found);
        Assert.NotNull(error);
        Assert.Empty(_db.FindingTriages);
    }

    [Fact]
    public async Task Another_users_project_and_unknown_advisories_are_not_found()
    {
        Assert.False((await _triage.SetAsync(_otherUserId, _projectId, _vulnId, TriageStatus.Ignored, null, default)).Found);
        Assert.False((await _triage.SetAsync(_userId, _projectId, Guid.NewGuid(), TriageStatus.Ignored, null, default)).Found);
        Assert.False(await _triage.ClearAsync(_otherUserId, _projectId, _vulnId, default));
        Assert.Empty(_db.FindingTriages);
    }
}
