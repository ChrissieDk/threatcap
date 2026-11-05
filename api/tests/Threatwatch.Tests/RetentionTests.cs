using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Workers;

namespace Threatwatch.Tests;

public class RetentionTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 5, 0, 0, 0, TimeSpan.Zero);

    private static (RetentionService Service, IServiceProvider Provider) Build(bool dryRun)
    {
        var services = new ServiceCollection();
        var dbName = Guid.NewGuid().ToString();
        services.AddDbContext<ThreatwatchDbContext>(o => o.UseInMemoryDatabase(dbName));
        var provider = services.BuildServiceProvider();
        var svc = new RetentionService(provider.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new RetentionOptions { DryRun = dryRun }), NullLogger<RetentionService>.Instance);
        return (svc, provider);
    }

    private static Vulnerability Vuln(string id, int daysOld, bool kev = false, bool withdrawn = false, string? package = null)
    {
        var v = new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, IsKnownExploited = kev, IsWithdrawn = withdrawn,
            PublishedAt = Now.AddDays(-daysOld), ModifiedAt = Now.AddDays(-daysOld),
        };
        if (package is not null)
            v.AffectedPackages.Add(new AffectedPackage { Id = Guid.NewGuid(), Ecosystem = Ecosystem.Npm, PackageName = package, DisplayName = package });
        return v;
    }

    private static async Task Seed(IServiceProvider provider)
    {
        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var project = new Project { Id = Guid.NewGuid(), UserId = Guid.NewGuid(), Name = "app", CreatedAt = Now, UpdatedAt = Now };
        db.ProjectDependencies.Add(new ProjectDependency { Id = Guid.NewGuid(), ProjectId = project.Id, SourceFile = "package.json", Ecosystem = Ecosystem.Npm, Name = "lodash", DisplayName = "lodash" });
        var old = Vuln("OLD", 200, package: "left-pad");
        old.Events.Add(new VulnerabilityEvent { Id = Guid.NewGuid(), EventType = VulnerabilityEventType.Published, EventAt = Now.AddDays(-200), IngestedAt = Now });
        db.Vulnerabilities.AddRange(
            old,
            Vuln("FRESH", 10),
            Vuln("OLD-KEV", 400, kev: true),
            Vuln("OLD-PROJECT", 400, package: "lodash"),
            Vuln("WITHDRAWN", 40, withdrawn: true),
            Vuln("WITHDRAWN-RECENT", 5, withdrawn: true));
        var fresh = Vuln("FRESH-EVENTS", 1);
        fresh.Events.Add(new VulnerabilityEvent { Id = Guid.NewGuid(), EventType = VulnerabilityEventType.AdvisoryUpdated, EventAt = Now.AddDays(-100), IngestedAt = Now });
        fresh.Events.Add(new VulnerabilityEvent { Id = Guid.NewGuid(), EventType = VulnerabilityEventType.AdvisoryUpdated, EventAt = Now.AddDays(-1), IngestedAt = Now });
        fresh.Events.Add(new VulnerabilityEvent { Id = Guid.NewGuid(), EventType = VulnerabilityEventType.KnownExploitedAdded, EventAt = Now.AddDays(-300), IngestedAt = Now });
        db.Vulnerabilities.Add(fresh);
        db.SecurityIncidents.AddRange(
            new SecurityIncident { Id = Guid.NewGuid(), Type = IncidentType.Outage, ExternalId = "a", VendorSlug = "v", VendorName = "V", Title = "old", Status = IncidentStatus.Resolved, StartedAt = Now.AddDays(-300), ResolvedAt = Now.AddDays(-299), CreatedAt = Now, UpdatedAt = Now },
            new SecurityIncident { Id = Guid.NewGuid(), Type = IncidentType.Outage, ExternalId = "b", VendorSlug = "v", VendorName = "V", Title = "open", Status = IncidentStatus.Investigating, StartedAt = Now.AddDays(-300), CreatedAt = Now, UpdatedAt = Now });
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task DryRunReportsButDeletesNothing()
    {
        var (svc, provider) = Build(dryRun: true);
        await Seed(provider);
        var result = await svc.RunOnceAsync(Now, CancellationToken.None);

        Assert.Equal(new RetentionResult(1, 1, 1, 1), result);
        using var scope = provider.CreateScope();
        Assert.Equal(7, await scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>().Vulnerabilities.CountAsync());
    }

    [Fact]
    public async Task RemovesStaleAndWithdrawnButKeepsKevProjectAndFresh()
    {
        var (svc, provider) = Build(dryRun: false);
        await Seed(provider);
        await svc.RunOnceAsync(Now, CancellationToken.None);

        using var scope = provider.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        var left = await db.Vulnerabilities.Select(v => v.CanonicalId).OrderBy(x => x).ToListAsync();
        Assert.Equal(["FRESH", "FRESH-EVENTS", "OLD-KEV", "OLD-PROJECT", "WITHDRAWN-RECENT"], left);
        Assert.Equal(0, await db.AffectedPackages.CountAsync(p => p.PackageName == "left-pad"));

        var events = await db.VulnerabilityEvents.Select(e => e.EventType).ToListAsync();
        Assert.Equal(2, events.Count);
        Assert.Contains(VulnerabilityEventType.KnownExploitedAdded, events);
        Assert.Equal(["open"], await db.SecurityIncidents.Select(i => i.Title).ToListAsync());
    }
}
