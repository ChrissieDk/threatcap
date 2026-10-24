using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Data;

namespace Threatwatch.Tests;

public class DbSeederTests
{
    [Fact]
    public async Task SeedAsyncIsIdempotent()
    {
        var options = new DbContextOptionsBuilder<ThreatwatchDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        await using var db = new ThreatwatchDbContext(options);

        await DbSeeder.SeedAsync(db);
        var firstCount = await db.Technologies.CountAsync();

        await DbSeeder.SeedAsync(db);
        var secondCount = await db.Technologies.CountAsync();

        Assert.True(firstCount > 0);
        Assert.Equal(firstCount, secondCount);
    }
}
