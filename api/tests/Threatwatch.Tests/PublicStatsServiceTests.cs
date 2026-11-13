using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Services;

namespace Threatwatch.Tests;

public class PublicStatsServiceTests : IDisposable
{
    private readonly ThreatwatchDbContext _db = new(
        new DbContextOptionsBuilder<ThreatwatchDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);

    public void Dispose() => _db.Dispose();

    private void Add(string id, DateTimeOffset createdAt, bool withdrawn = false)
    {
        _db.Vulnerabilities.Add(new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, IsWithdrawn = withdrawn,
            PublishedAt = createdAt, ModifiedAt = createdAt, CreatedAt = createdAt, UpdatedAt = createdAt,
        });
        _db.SaveChanges();
    }

    [Fact]
    public async Task Counts_only_advisories_picked_up_since_the_date_and_skips_withdrawn_ones()
    {
        var since = new DateTimeOffset(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
        Add("old", since.AddDays(-1));
        Add("a", since.AddHours(1));
        Add("b", since.AddDays(2));
        Add("withdrawn", since.AddDays(1), withdrawn: true);

        var result = await new PublicStatsService(_db).GetAsync(since, default);

        Assert.Equal((2, since), (result.VulnerabilitiesPickedUp, result.Since));
    }

    [Fact]
    public async Task Without_a_date_counts_everything_and_reports_the_first_ingest()
    {
        var first = new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
        Add("a", first);
        Add("b", first.AddDays(5));

        var result = await new PublicStatsService(_db).GetAsync(null, default);

        Assert.Equal((2, (DateTimeOffset?)first), (result.VulnerabilitiesPickedUp, result.Since));
    }

    [Fact]
    public async Task Empty_database_has_no_start_date()
    {
        var result = await new PublicStatsService(_db).GetAsync(null, default);
        Assert.Equal((0, (DateTimeOffset?)null), (result.VulnerabilitiesPickedUp, result.Since));
    }
}
