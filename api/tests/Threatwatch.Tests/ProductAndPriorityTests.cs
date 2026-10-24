using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class ProductAndPriorityTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly VulnerabilityUpserter _upserter;

    public ProductAndPriorityTests()
    {
        var options = new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ThreatwatchDbContext(options);
        _upserter = new VulnerabilityUpserter(_db, NullLogger<VulnerabilityUpserter>.Instance);
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task KevUpsertPersistsVendorAndProduct()
    {
        var since = new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero);

        await _upserter.UpsertKnownExploitedAsync(
            "CVE-2024-1000", "KEV title", "desc", since, "https://cisa.gov/kev",
            CancellationToken.None, vendorProject: "Adobe", product: "Acrobat Reader");

        var vuln = await _db.Vulnerabilities.SingleAsync();
        Assert.Equal("Adobe", vuln.PrimaryVendor);
        Assert.Equal("Acrobat Reader", vuln.PrimaryProduct);
        Assert.Null(vuln.ProductType);
    }

    [Fact]
    public async Task OsvUpsertDerivesProductFromScopedNpmPackage()
    {
        var record = new OsvRecord
        {
            Id = "GHSA-aaaa-bbbb-cccc",
            Summary = "Scoped package advisory",
            Aliases = ["CVE-2024-2000"],
            Published = "2024-02-01T00:00:00Z",
            Modified = "2024-02-02T00:00:00Z",
            Affected =
            [
                new OsvAffected
                {
                    Package = new OsvPackage { Ecosystem = "npm", Name = "@babel/core" },
                    Ranges =
                    [
                        new OsvRange
                        {
                            Type = "ECOSYSTEM",
                            Events = [new OsvRangeEvent { Introduced = "0" }],
                        },
                    ],
                },
            ],
        };

        await _upserter.UpsertOsvRecordAsync(record, CancellationToken.None);

        var vuln = await _db.Vulnerabilities.SingleAsync();
        Assert.Equal("babel", vuln.PrimaryVendor);
        Assert.Equal("@babel/core", vuln.PrimaryProduct);
        Assert.Equal(ProductType.Library, vuln.ProductType);
    }

    [Fact]
    public async Task OsvUpsertPrefersPackageWithFixedVersions()
    {
        var record = new OsvRecord
        {
            Id = "CVE-2024-3000",
            Summary = "Multi-package advisory",
            Published = "2024-02-01T00:00:00Z",
            Modified = "2024-02-02T00:00:00Z",
            Affected =
            [
                new OsvAffected
                {
                    Package = new OsvPackage { Ecosystem = "PyPI", Name = "unrelated" },
                    Ranges = [new OsvRange { Type = "ECOSYSTEM", Events = [new OsvRangeEvent { Introduced = "0" }] }],
                },
                new OsvAffected
                {
                    Package = new OsvPackage { Ecosystem = "PyPI", Name = "django" },
                    Ranges =
                    [
                        new OsvRange
                        {
                            Type = "ECOSYSTEM",
                            Events =
                            [
                                new OsvRangeEvent { Introduced = "0" },
                                new OsvRangeEvent { Fixed = "4.2.10" },
                            ],
                        },
                    ],
                },
            ],
        };

        await _upserter.UpsertOsvRecordAsync(record, CancellationToken.None);

        var vuln = await _db.Vulnerabilities.SingleAsync();
        Assert.Equal("django", vuln.PrimaryProduct);
        Assert.Equal(ProductType.Library, vuln.ProductType);
    }

    [Fact]
    public async Task PriorityScoreIsComputedFromCvssEpssAndKev()
    {
        var since = new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero);
        await _upserter.UpsertKnownExploitedAsync(
            "CVE-2024-4000", "KEV", null, since, "https://cisa.gov/kev", CancellationToken.None);

        var record = new OsvRecord
        {
            Id = "GHSA-dddd-eeee-ffff",
            Summary = "Critical advisory",
            Aliases = ["CVE-2024-4000"],
            Published = "2024-02-01T00:00:00Z",
            Modified = "2024-02-02T00:00:00Z",
            Severity = [new OsvSeverity { Type = "CVSS_V3", Score = "10.0" }],
        };
        await _upserter.UpsertOsvRecordAsync(record, CancellationToken.None);

        Assert.Equal(20.0, await PriorityOf("CVE-2024-4000"));

        Assert.True(await _upserter.UpdateEpssAsync("CVE-2024-4000", 0.5, 0.97, CancellationToken.None));
        Assert.Equal(30.0, await PriorityOf("CVE-2024-4000"));

        Assert.True(await _upserter.UpdateEpssAsync("CVE-2024-4000", 0.1, 0.5, CancellationToken.None));
        Assert.Equal(22.0, await PriorityOf("CVE-2024-4000"));
    }

    [Fact]
    public async Task PriorityScoreIsNullWithoutCvss()
    {
        await _upserter.UpdateEpssAsync("CVE-2024-5000", 0.9, 0.99, CancellationToken.None);
        await _upserter.UpsertKnownExploitedAsync(
            "CVE-2024-5000", "KEV", null,
            new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero),
            "https://cisa.gov/kev", CancellationToken.None);
        await _upserter.UpdateEpssAsync("CVE-2024-5000", 0.9, 0.99, CancellationToken.None);

        Assert.Null(await PriorityOf("CVE-2024-5000"));
    }

    [Fact]
    public async Task UpdateEpssIsIdempotentForUnchangedScores()
    {
        var since = new DateTimeOffset(2024, 3, 1, 0, 0, 0, TimeSpan.Zero);
        await _upserter.UpsertKnownExploitedAsync(
            "CVE-2024-6000", "KEV", null, since, "https://cisa.gov/kev", CancellationToken.None);

        Assert.True(await _upserter.UpdateEpssAsync("CVE-2024-6000", 0.4, 0.9, CancellationToken.None));
        Assert.False(await _upserter.UpdateEpssAsync("CVE-2024-6000", 0.4, 0.9, CancellationToken.None));
    }

    private async Task<double?> PriorityOf(string canonicalId) =>
        await _db.Vulnerabilities.Where(v => v.CanonicalId == canonicalId)
            .Select(v => v.PriorityScore)
            .SingleAsync();
}

public class DashboardActNowTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly DashboardService _dashboard;
    private readonly Guid _userId = Guid.NewGuid();

    public DashboardActNowTests()
    {
        var options = new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ThreatwatchDbContext(options);
        _dashboard = new DashboardService(_db, new FollowService(_db));

        var tech = new Technology
        {
            Id = Guid.NewGuid(),
            Name = "Django",
            Slug = "django",
            Type = TechnologyType.Package,
            Ecosystem = Ecosystem.PyPI,
            Aliases = [],
        };
        _db.Users.Add(new UserAccount
        {
            Id = _userId,
            Email = "dev@example.com",
            UserName = "dev@example.com",
            DisplayName = "Dev",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        _db.Technologies.Add(tech);
        _db.UserFollows.Add(new UserFollow
        {
            Id = Guid.NewGuid(),
            UserId = _userId,
            TechnologyId = tech.Id,
            CreatedAt = DateTimeOffset.UtcNow,
        });

        _db.Vulnerabilities.AddRange(
            Vuln("CVE-2024-7001", "django", priority: 25.0, publishedDaysAgo: 5),
            Vuln("CVE-2024-7002", "django", priority: 30.0, publishedDaysAgo: 90),
            Vuln("CVE-2024-7003", "flask", priority: 40.0, publishedDaysAgo: 5),
            Vuln("CVE-2024-7004", "django", priority: null, publishedDaysAgo: 5));
        _db.SaveChanges();
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task ActNowReturnsFollowedTechVulnsRankedByPriority()
    {
        var items = await _dashboard.GetActNowAsync(10, 30, _userId, CancellationToken.None);

        Assert.Single(items);
        Assert.Equal("CVE-2024-7001", items[0].CanonicalId);
        Assert.Equal(25.0, items[0].PriorityScore);
        Assert.Equal("django", items[0].PrimaryProduct);
        Assert.Equal(ProductType.Library, items[0].ProductType);
    }

    [Fact]
    public async Task ActNowExcludesStaleNonKevVulns()
    {
        var items = await _dashboard.GetActNowAsync(10, 30, _userId, CancellationToken.None);

        Assert.DoesNotContain(items, i => i.CanonicalId == "CVE-2024-7002");
    }

    [Fact]
    public async Task ActNowReturnsEmptyWhenUserFollowsNothing()
    {
        var items = await _dashboard.GetActNowAsync(10, 30, Guid.NewGuid(), CancellationToken.None);

        Assert.Empty(items);
    }

    private static Vulnerability Vuln(string id, string package, double? priority, int publishedDaysAgo)
    {
        var now = DateTimeOffset.UtcNow;
        var vuln = new Vulnerability
        {
            Id = Guid.NewGuid(),
            CanonicalId = id,
            Title = id,
            Severity = Severity.High,
            CvssScore = 7.5m,
            PriorityScore = priority,
            PublishedAt = now.AddDays(-publishedDaysAgo),
            ModifiedAt = now,
            CreatedAt = now,
            UpdatedAt = now,
            PrimaryProduct = package,
            ProductType = ProductType.Library,
        };
        vuln.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(),
            VulnerabilityId = vuln.Id,
            Ecosystem = Ecosystem.PyPI,
            PackageName = package,
            DisplayName = package,
        });
        return vuln;
    }
}
