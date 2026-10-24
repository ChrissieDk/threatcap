using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Services;

namespace Threatwatch.Tests;

public class FollowServiceTests : IDisposable
{
    private readonly ThreatwatchDbContext _db;
    private readonly FollowService _follows;
    private readonly Guid _userId = Guid.NewGuid();

    public FollowServiceTests()
    {
        var options = new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        _db = new ThreatwatchDbContext(options);
        _db.Users.Add(new UserAccount
        {
            Id = _userId,
            Email = "dev@example.com",
            UserName = "dev@example.com",
            DisplayName = "Dev",
            CreatedAt = DateTimeOffset.UtcNow,
        });
        _db.Technologies.AddRange(
            new Technology
            {
                Id = Guid.NewGuid(),
                Name = "React",
                Slug = "react",
                Type = TechnologyType.Framework,
                Ecosystem = Ecosystem.Npm,
                Aliases = [],
            },
            new Technology
            {
                Id = Guid.NewGuid(),
                Name = "npm",
                Slug = "npm",
                Type = TechnologyType.Ecosystem,
                Ecosystem = Ecosystem.Npm,
                Aliases = ["npmjs"],
            },
            new Technology
            {
                Id = Guid.NewGuid(),
                Name = "lodash",
                Slug = "pkg-lodash",
                Type = TechnologyType.Package,
                Ecosystem = Ecosystem.Npm,
                Aliases = [],
            });
        _db.SaveChanges();
        _follows = new FollowService(_db);
    }

    public void Dispose() => _db.Dispose();

    [Fact]
    public async Task FollowIsIdempotentAndListsTheTechnology()
    {
        var first = await _follows.FollowAsync(_userId, "react", CancellationToken.None);
        var second = await _follows.FollowAsync(_userId, "react", CancellationToken.None);

        Assert.NotNull(first);
        Assert.Equal("react", first.Slug);
        Assert.Equal(first.Id, second!.Id);
        Assert.Equal(1, await _db.UserFollows.CountAsync());

        var list = await _follows.ListAsync(_userId, 7, CancellationToken.None);
        Assert.Single(list);
        Assert.Equal("react", list[0].Slug);
    }

    [Fact]
    public async Task FollowUnknownSlugReturnsNull()
    {
        Assert.Null(await _follows.FollowAsync(_userId, "missing", CancellationToken.None));
    }

    [Fact]
    public async Task UnfollowRemovesTheRowAndUnknownTechIsReported()
    {
        await _follows.FollowAsync(_userId, "react", CancellationToken.None);
        Assert.True(await _follows.UnfollowAsync(_userId, "react", CancellationToken.None));
        Assert.Equal(0, await _db.UserFollows.CountAsync());
        Assert.True(await _follows.UnfollowAsync(_userId, "react", CancellationToken.None));
        Assert.False(await _follows.UnfollowAsync(_userId, "missing", CancellationToken.None));
    }

    [Fact]
    public async Task RecentActivityCountsMatchingPackages()
    {
        var vuln = new Vulnerability
        {
            Id = Guid.NewGuid(),
            CanonicalId = "CVE-2024-1",
            Title = "lodash issue",
            PublishedAt = DateTimeOffset.UtcNow.AddDays(-1),
            ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        vuln.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(),
            VulnerabilityId = vuln.Id,
            Ecosystem = Ecosystem.Npm,
            PackageName = "lodash",
            DisplayName = "lodash",
        });
        _db.Vulnerabilities.Add(vuln);
        await _db.SaveChangesAsync();

        await _follows.FollowAsync(_userId, "pkg-lodash", CancellationToken.None);
        await _follows.FollowAsync(_userId, "npm", CancellationToken.None);
        await _follows.FollowAsync(_userId, "react", CancellationToken.None);

        var list = await _follows.ListAsync(_userId, 7, CancellationToken.None);
        Assert.Equal(1, list.Single(f => f.Slug == "pkg-lodash").RecentActivityCount);
        Assert.Equal(1, list.Single(f => f.Slug == "npm").RecentActivityCount);
        Assert.Equal(0, list.Single(f => f.Slug == "react").RecentActivityCount);
    }

    [Fact]
    public async Task ReactFollowCountsReactDomAdvisories()
    {
        var vuln = new Vulnerability
        {
            Id = Guid.NewGuid(),
            CanonicalId = "CVE-2024-react",
            Title = "react-dom issue",
            Severity = Severity.High,
            PublishedAt = DateTimeOffset.UtcNow.AddDays(-1),
            ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        vuln.AffectedPackages.Add(new AffectedPackage
        {
            Id = Guid.NewGuid(),
            VulnerabilityId = vuln.Id,
            Ecosystem = Ecosystem.Npm,
            PackageName = "react-dom",
            DisplayName = "react-dom",
        });
        _db.Vulnerabilities.Add(vuln);
        await _db.SaveChangesAsync();

        await _follows.FollowAsync(_userId, "react", CancellationToken.None);
        var list = await _follows.ListAsync(_userId, 7, CancellationToken.None);
        var react = list.Single(f => f.Slug == "react");
        Assert.Equal(1, react.RecentActivityCount);
        Assert.Equal(1, react.CriticalHighCount);
        Assert.Equal(0, react.KevCount);
    }

    [Fact]
    public async Task FollowPackageCreatesACatalogEntryWhenNeeded()
    {
        var follow = await _follows.FollowPackageAsync(_userId, "Npm", "left-pad", CancellationToken.None);
        Assert.NotNull(follow);
        Assert.Equal("pkg-left-pad", follow.Slug);
        Assert.Equal(1, await _db.UserFollows.CountAsync());
        Assert.True(await _db.Technologies.AnyAsync(t => t.Slug == "pkg-left-pad"));
    }

    [Fact]
    public async Task FollowPackageMapsToExistingCatalogTechnology()
    {
        var follow = await _follows.FollowPackageAsync(_userId, "Npm", "react-dom", CancellationToken.None);
        Assert.NotNull(follow);
        Assert.Equal("react", follow.Slug);
        Assert.False(await _db.Technologies.AnyAsync(t => t.Slug == "pkg-react-dom"));
    }
}

public class TechnologyPackageMatcherTests
{
    [Fact]
    public void EcosystemFollowMatchesEveryPackageInThatEcosystem()
    {
        var npm = new Technology
        {
            Name = "npm",
            Slug = "npm",
            Type = TechnologyType.Ecosystem,
            Ecosystem = Ecosystem.Npm,
        };
        Assert.True(TechnologyPackageMatcher.Matches(npm, Ecosystem.Npm, "left-pad"));
        Assert.False(TechnologyPackageMatcher.Matches(npm, Ecosystem.PyPI, "left-pad"));
    }

    [Fact]
    public void PackageFollowMatchesNameSlugAndAliases()
    {
        var next = new Technology
        {
            Name = "next",
            Slug = "pkg-next",
            Type = TechnologyType.Package,
            Ecosystem = Ecosystem.Npm,
            Aliases = ["nextjs"],
        };
        Assert.True(TechnologyPackageMatcher.Matches(next, Ecosystem.Npm, "next"));
        Assert.True(TechnologyPackageMatcher.Matches(next, Ecosystem.Npm, "nextjs"));
        Assert.False(TechnologyPackageMatcher.Matches(next, Ecosystem.Npm, "react"));
        Assert.False(TechnologyPackageMatcher.Matches(next, Ecosystem.PyPI, "next"));
    }

    [Fact]
    public void FrameworkFollowMatchesScopedAndPrefixedPackages()
    {
        var react = new Technology
        {
            Name = "React",
            Slug = "react",
            Type = TechnologyType.Framework,
            Ecosystem = Ecosystem.Npm,
            Aliases = [],
        };
        Assert.True(TechnologyPackageMatcher.Matches(react, Ecosystem.Npm, "react"));
        Assert.True(TechnologyPackageMatcher.Matches(react, Ecosystem.Npm, "react-dom"));
        Assert.True(TechnologyPackageMatcher.Matches(react, Ecosystem.Npm, "@types/react"));
        Assert.False(TechnologyPackageMatcher.Matches(react, Ecosystem.Npm, "preact"));
        Assert.False(TechnologyPackageMatcher.Matches(react, Ecosystem.Npm, "create-react-app"));
    }

    [Fact]
    public void ShortAliasesDoNotPrefixMatch()
    {
        var typescript = new Technology
        {
            Name = "TypeScript",
            Slug = "typescript",
            Type = TechnologyType.Language,
            Aliases = ["ts"],
        };
        Assert.True(TechnologyPackageMatcher.Matches(typescript, Ecosystem.Npm, "typescript"));
        Assert.True(TechnologyPackageMatcher.Matches(typescript, Ecosystem.Npm, "ts"));
        Assert.False(TechnologyPackageMatcher.Matches(typescript, Ecosystem.Npm, "tslib"));
        Assert.False(TechnologyPackageMatcher.Matches(typescript, Ecosystem.Npm, "ts-node"));
    }
}
