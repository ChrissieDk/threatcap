using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Data;

public static class DbSeeder
{
    private static readonly (string Name, string Slug, TechnologyType Type, Ecosystem? Eco, string[] Aliases)[] SeedTechnologies =
    [
        ("TypeScript", "typescript", TechnologyType.Language, null, ["ts"]),
        ("JavaScript", "javascript", TechnologyType.Language, null, ["js", "ecmascript"]),
        ("C#", "csharp", TechnologyType.Language, null, ["cs", "c-sharp"]),
        ("Python", "python", TechnologyType.Language, Ecosystem.PyPI, ["py"]),
        ("Java", "java", TechnologyType.Language, Ecosystem.Maven, []),
        ("Go", "go", TechnologyType.Language, Ecosystem.Go, ["golang"]),

        ("React", "react", TechnologyType.Framework, Ecosystem.Npm, []),
        ("Next.js", "nextjs", TechnologyType.Framework, Ecosystem.Npm, ["next", "nextjs"]),
        ("Node.js", "nodejs", TechnologyType.Runtime, Ecosystem.Npm, ["node"]),
        ("ASP.NET Core", "aspnet-core", TechnologyType.Framework, Ecosystem.NuGet, ["dotnet", "aspnetcore"]),
        ("Django", "django", TechnologyType.Framework, Ecosystem.PyPI, []),

        ("npm", "npm", TechnologyType.Ecosystem, Ecosystem.Npm, ["npmjs"]),
        ("NuGet", "nuget", TechnologyType.Ecosystem, Ecosystem.NuGet, []),
        ("PyPI", "pypi", TechnologyType.Ecosystem, Ecosystem.PyPI, ["pip", "python-package-index"]),
        ("Maven", "maven", TechnologyType.Ecosystem, Ecosystem.Maven, []),
        ("Cargo", "cargo", TechnologyType.Ecosystem, Ecosystem.Cargo, ["crates"]),

        ("next", "pkg-next", TechnologyType.Package, Ecosystem.Npm, ["nextjs"]),
        ("react", "pkg-react", TechnologyType.Package, Ecosystem.Npm, []),
        ("lodash", "pkg-lodash", TechnologyType.Package, Ecosystem.Npm, []),

        ("Docker", "docker", TechnologyType.Infrastructure, null, []),
        ("PostgreSQL", "postgresql", TechnologyType.Infrastructure, null, ["postgres", "pgsql"]),
        ("GitHub", "github", TechnologyType.Infrastructure, null, ["gh", "github.com"]),
        ("GitHub Actions", "github-actions", TechnologyType.Ecosystem, Ecosystem.GithubActions, ["gha", "actions"]),
        ("Cloudflare", "cloudflare", TechnologyType.Infrastructure, null, ["cf"]),
    ];

    public static async Task SeedAsync(ThreatwatchDbContext db, CancellationToken ct = default)
    {
        var existingSlugs = (await db.Technologies
            .Select(t => t.Slug)
            .ToListAsync(ct))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, slug, type, eco, aliases) in SeedTechnologies)
        {
            if (existingSlugs.Contains(slug))
            {
                continue;
            }

            db.Technologies.Add(new Technology
            {
                Id = Guid.NewGuid(),
                Name = name,
                Slug = slug,
                Type = type,
                Ecosystem = eco,
                Aliases = aliases,
            });
        }

        await db.SaveChangesAsync(ct);
    }
}

public sealed class DbSeederHostedService(
    IServiceScopeFactory scopeFactory,
    ILogger<DbSeederHostedService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
        await DbSeeder.SeedAsync(db, cancellationToken);
        logger.LogInformation("Technology seed data upserted.");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
