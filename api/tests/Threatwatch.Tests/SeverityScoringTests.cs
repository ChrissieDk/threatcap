using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Core.Scoring;
using Threatwatch.Ingestion.Providers;
using Threatwatch.Ingestion.Workers;

namespace Threatwatch.Tests;

public class CvssCalculatorTests
{
    [Theory]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)]
    [InlineData("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5)]
    [InlineData("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6)]
    [InlineData("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5)]
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0)]
    public void Scores_known_vectors(string vector, double expected) =>
        Assert.Equal((decimal)expected, CvssCalculator.ScoreV3(vector));

    [Theory]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")]
    [InlineData("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("AV:N/AC:L/Au:N/C:P/I:P/A:P")]
    [InlineData("")]
    [InlineData(null)]
    public void Does_not_score_unsupported_or_malformed_vectors(string? vector) =>
        Assert.Null(CvssCalculator.ScoreV3(vector));
}

public class CvssV4CalculatorTests
{
    [Theory]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3)]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0)]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0)]
    public void Scores_known_vectors(string vector, double expected) =>
        Assert.Equal((decimal)expected, CvssV4Calculator.ScoreV4(vector));

    [Fact]
    public void Threat_metrics_can_only_lower_the_score()
    {
        const string baseVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N";
        var exploited = CvssV4Calculator.ScoreV4(baseVector + "/E:A")!.Value;
        var poc = CvssV4Calculator.ScoreV4(baseVector + "/E:P")!.Value;
        var unreported = CvssV4Calculator.ScoreV4(baseVector + "/E:U")!.Value;

        Assert.Equal(CvssV4Calculator.ScoreV4(baseVector), exploited);
        Assert.True(poc < exploited && unreported < poc);
    }

    [Fact]
    public void Harder_attack_conditions_lower_the_score()
    {
        var easy = CvssV4Calculator.ScoreV4("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")!.Value;
        var hard = CvssV4Calculator.ScoreV4("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")!.Value;
        Assert.InRange(hard, 0.1m, easy - 0.1m);
    }

    [Theory]
    [InlineData("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H")] // missing metrics
    [InlineData("CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")] // invalid value
    [InlineData("CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")] // duplicate metric
    [InlineData("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")]
    [InlineData("")]
    [InlineData(null)]
    public void Does_not_score_malformed_or_non_v4_vectors(string? vector) =>
        Assert.Null(CvssV4Calculator.ScoreV4(vector));
}

public class OsvSeverityTests
{
    private static OsvRecord Parse(string json) => JsonSerializer.Deserialize<OsvRecord>(json)!;

    [Fact]
    public void V3_vector_is_scored_not_read_as_a_version_number()
    {
        var info = Parse("""{"id":"GHSA-x","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}""").BestSeverity()!.Value;
        Assert.Equal((9.8m, Severity.Critical, "CVSS_V3"), (info.Score, info.Band, info.Source));
    }

    [Fact]
    public void V4_only_is_scored_from_the_vector_ahead_of_the_label()
    {
        var info = Parse("""{"id":"GHSA-x","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],"database_specific":{"severity":"HIGH"}}""").BestSeverity()!.Value;
        Assert.Equal((9.3m, Severity.Critical, "CVSS_V4"), (info.Score, info.Band, info.Source));
        Assert.StartsWith("CVSS:4.0", info.Vector);
    }

    [Fact]
    public void V3_wins_when_an_advisory_carries_both()
    {
        var info = Parse("""{"id":"x","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]}""").BestSeverity()!.Value;
        Assert.Equal((6.5m, "CVSS_V3"), (info.Score, info.Source));
    }

    [Fact]
    public void Unscorable_v4_uses_the_label_and_keeps_the_vector()
    {
        var info = Parse("""{"id":"GHSA-x","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}],"database_specific":{"severity":"HIGH"}}""").BestSeverity()!.Value;
        Assert.Null(info.Score);
        Assert.Equal((Severity.High, "CVSS_V4"), (info.Band, info.Source));
        Assert.StartsWith("CVSS:4.0", info.Vector);
    }

    [Fact]
    public void Unscorable_v4_without_a_label_stays_unrated_instead_of_guessing()
    {
        var info = Parse("""{"id":"x","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}]}""").BestSeverity()!.Value;
        Assert.Equal((null, Severity.Unknown), (info.Score, info.Band));
    }

    [Theory]
    [InlineData("MODERATE", Severity.Medium)]
    [InlineData("critical", Severity.Critical)]
    [InlineData("LOW", Severity.Low)]
    public void Label_only_advisories_get_a_band(string label, Severity expected) =>
        Assert.Equal(expected, Parse("{\"id\":\"x\",\"database_specific\":{\"severity\":\"" + label + "\"}}").BestSeverity()!.Value.Band);

    [Fact]
    public void No_severity_data_returns_null() =>
        Assert.Null(Parse("""{"id":"x"}""").BestSeverity());
}

public class PriorityScoringTests
{
    [Fact]
    public void Falls_back_to_severity_and_ranks_unrated_exploited_advisories()
    {
        Assert.Equal(9.8, PriorityScoring.Compute(9.8m, Severity.Critical, null, false));
        Assert.Equal(8.0, PriorityScoring.Compute(null, Severity.High, null, false));
        Assert.Equal(14.0, PriorityScoring.Compute(null, Severity.Unknown, null, true));
        Assert.Null(PriorityScoring.Compute(null, Severity.Unknown, 0.9, false));
    }
}

public class SeverityRepairServiceTests
{
    [Fact]
    public async Task Rescoring_fixes_v3_scores_v4_and_runs_once()
    {
        var services = new ServiceCollection();
        var dbName = Guid.NewGuid().ToString();
        services.AddDbContext<ThreatwatchDbContext>(o => o.UseInMemoryDatabase(dbName));
        var provider = services.BuildServiceProvider();

        Vulnerability Make(string id, string source, string? vector, decimal score, Severity sev, bool kev = false) => new()
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, CvssSource = source, CvssVector = vector, CvssScore = score,
            Severity = sev, IsKnownExploited = kev, PublishedAt = DateTimeOffset.UtcNow, ModifiedAt = DateTimeOffset.UtcNow,
            CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
        };

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
            db.Vulnerabilities.AddRange(
                Make("V3", "CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 3.1m, Severity.Low),
                Make("V4", "CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 4.0m, Severity.Medium, kev: true));
            db.IngestionStates.Add(new IngestionState { Id = Guid.NewGuid(), Source = IngestionSource.Osv, Watermark = "2026-01-01T00:00:00Z" });
            await db.SaveChangesAsync();
        }

        var repair = new SeverityRepairService(provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<SeverityRepairService>.Instance);
        await repair.RunAsync(default);

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
            var v3 = db.Vulnerabilities.Single(v => v.CanonicalId == "V3");
            Assert.Equal((9.8m, Severity.Critical), (v3.CvssScore, v3.Severity));
            Assert.Equal(9.8, v3.PriorityScore);

            var v4 = db.Vulnerabilities.Single(v => v.CanonicalId == "V4");
            Assert.Equal((9.3m, Severity.Critical), (v4.CvssScore, v4.Severity));
            Assert.Equal(18.6, v4.PriorityScore!.Value, 5); // 9.3 x 2 (exploited)
            Assert.NotNull(db.IngestionStates.Single().Watermark); // nothing needed re-reading

            // A later run changes nothing.
            v3.CvssScore = 1m;
            await db.SaveChangesAsync();
        }

        await repair.RunAsync(default);
        using var check = provider.CreateScope();
        Assert.Equal(1m, check.ServiceProvider.GetRequiredService<ThreatwatchDbContext>().Vulnerabilities.Single(v => v.CanonicalId == "V3").CvssScore);
    }

    [Fact]
    public async Task V4_pass_scores_rows_cleared_by_the_earlier_repair()
    {
        var services = new ServiceCollection();
        var dbName = Guid.NewGuid().ToString();
        services.AddDbContext<ThreatwatchDbContext>(o => o.UseInMemoryDatabase(dbName));
        var provider = services.BuildServiceProvider();

        using (var scope = provider.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ThreatwatchDbContext>();
            db.AppSettings.Add(new AppSetting { Key = SeverityRepairService.SettingKey, ProtectedValue = "done", UpdatedAt = DateTimeOffset.UtcNow });
            db.Vulnerabilities.Add(new Vulnerability
            {
                Id = Guid.NewGuid(), CanonicalId = "V4", Title = "V4", CvssSource = "CVSS_V4",
                CvssVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                Severity = Severity.Unknown, PublishedAt = DateTimeOffset.UtcNow, ModifiedAt = DateTimeOffset.UtcNow,
                CreatedAt = DateTimeOffset.UtcNow, UpdatedAt = DateTimeOffset.UtcNow,
            });
            await db.SaveChangesAsync();
        }

        await new SeverityRepairService(provider.GetRequiredService<IServiceScopeFactory>(), NullLogger<SeverityRepairService>.Instance).RunAsync(default);

        using var check = provider.CreateScope();
        var row = check.ServiceProvider.GetRequiredService<ThreatwatchDbContext>().Vulnerabilities.Single();
        Assert.Equal((9.3m, Severity.Critical), (row.CvssScore, row.Severity));
    }
}
