using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class NvdDataSourceTests : IDisposable
{
    private readonly ServiceProvider _services;
    private readonly ThreatwatchDbContext _db;
    private readonly StubHandler _handler = new();
    private readonly NvdDataSource _source;

    public NvdDataSourceTests()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddDbContext<ThreatwatchDbContext>(o => o.UseInMemoryDatabase(dbName));
        services.AddScoped<VulnerabilityUpserter>(sp =>
            new VulnerabilityUpserter(sp.GetRequiredService<ThreatwatchDbContext>(), NullLogger<VulnerabilityUpserter>.Instance));
        _services = services.BuildServiceProvider();
        _db = _services.GetRequiredService<ThreatwatchDbContext>();

        _source = new NvdDataSource(
            new HttpClient(_handler) { BaseAddress = new Uri("https://services.nvd.nist.gov/") },
            Options.Create(new NvdOptions { ApiKey = "test-key", MaxPerRun = 2 }),
            NullLogger<NvdDataSource>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _services.Dispose();
    }

    private Vulnerability Add(string id, decimal? score = null, int ageDays = 1, string? cveAlias = null)
    {
        var published = DateTimeOffset.UtcNow.AddDays(-ageDays);
        var vuln = new Vulnerability
        {
            Id = Guid.NewGuid(), CanonicalId = id, Title = id, CvssScore = score,
            Severity = score is null ? Severity.Unknown : Severity.Low,
            PublishedAt = published, ModifiedAt = published, CreatedAt = published, UpdatedAt = published,
        };
        if (cveAlias is not null)
        {
            vuln.Aliases.Add(new VulnerabilityAlias { Id = Guid.NewGuid(), VulnerabilityId = vuln.Id, Alias = cveAlias, AliasType = AliasType.Cve });
        }

        _db.Vulnerabilities.Add(vuln);
        _db.SaveChanges();
        return vuln;
    }

    private async Task<IngestionResultSummary> RunAsync()
    {
        using var scope = _services.CreateScope();
        var result = await _source.SyncAsync(scope, default);
        return new IngestionResultSummary(result.RecordsProcessed, result.Error);
    }

    private sealed record IngestionResultSummary(int Records, string? Error);

    private const string V31Response = """
        {"vulnerabilities":[{"cve":{"id":"CVE-2026-1000","metrics":{"cvssMetricV31":[
          {"type":"Primary","cvssData":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8}}]}}}]}
        """;

    [Fact]
    public async Task Rates_an_unrated_cve_and_records_the_source()
    {
        _handler.RespondWithJson("CVE-2026-1000", V31Response);
        var vuln = Add("CVE-2026-1000");

        var result = await RunAsync();

        Assert.Equal(1, result.Records);
        var saved = await _db.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id);
        Assert.Equal((9.8m, Severity.Critical, "CVSS_V3"), (saved.CvssScore, saved.Severity, saved.CvssSource));
        Assert.StartsWith("CVSS:3.1", saved.CvssVector);
        Assert.Equal(9.8, saved.PriorityScore);
        Assert.Contains(await _db.SourceReferences.ToListAsync(), r => r.SourceType == SourceType.Nvd && r.VulnerabilityId == vuln.Id);
    }

    [Fact]
    public async Task Looks_up_a_ghsa_advisory_through_its_cve_alias()
    {
        _handler.RespondWithJson("CVE-2026-1000", V31Response);
        var vuln = Add("GHSA-aaaa-bbbb-cccc", cveAlias: "CVE-2026-1000");

        await RunAsync();

        Assert.Equal(9.8m, (await _db.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id)).CvssScore);
    }

    [Fact]
    public async Task Leaves_rated_advisories_alone()
    {
        var vuln = Add("CVE-2026-1000", score: 3.1m);

        var result = await RunAsync();

        Assert.Equal(0, result.Records);
        Assert.Equal(3.1m, (await _db.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id)).CvssScore);
    }

    [Fact]
    public async Task Cves_without_nvd_metrics_stay_unrated()
    {
        _handler.RespondWithJson("CVE-2026-1000", """{"vulnerabilities":[{"cve":{"id":"CVE-2026-1000","metrics":{}}}]}""");
        var vuln = Add("CVE-2026-1000");

        var result = await RunAsync();

        Assert.Equal(0, result.Records);
        Assert.Null((await _db.Vulnerabilities.AsNoTracking().SingleAsync(v => v.Id == vuln.Id)).CvssScore);
    }

    [Fact]
    public async Task Skips_advisories_older_than_the_lookback_window()
    {
        _handler.RespondWithJson("CVE-2026-1000", V31Response);
        Add("CVE-2026-1000", ageDays: 90);

        Assert.Equal(0, (await RunAsync()).Records);
    }

    [Fact]
    public async Task A_rate_limit_stops_the_pass_without_failing_it()
    {
        _handler.RespondWithStatus("CVE-2026-1000", HttpStatusCode.Forbidden);
        Add("CVE-2026-1000");

        var result = await RunAsync();

        Assert.Equal((0, null), (result.Records, result.Error));
    }

    [Fact]
    public async Task The_cursor_walks_older_candidates_then_starts_over()
    {
        _handler.RespondWithJson("CVE-2026-0001", """{"vulnerabilities":[]}""");
        _handler.RespondWithJson("CVE-2026-0002", """{"vulnerabilities":[]}""");
        _handler.RespondWithJson("CVE-2026-0003", """{"vulnerabilities":[]}""");
        Add("CVE-2026-0001", ageDays: 1);
        Add("CVE-2026-0002", ageDays: 2);
        Add("CVE-2026-0003", ageDays: 3);

        await RunAsync(); // MaxPerRun = 2: looks at 0001 and 0002
        Assert.NotNull((await _db.IngestionStates.AsNoTracking().SingleAsync(s => s.Source == IngestionSource.Nvd)).Watermark);

        await RunAsync(); // only 0003 is left, a short page, so the cursor resets
        Assert.Null((await _db.IngestionStates.AsNoTracking().SingleAsync(s => s.Source == IngestionSource.Nvd)).Watermark);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);

        public void RespondWithJson(string cveId, string json) =>
            _routes[cveId] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

        public void RespondWithStatus(string cveId, HttpStatusCode status) =>
            _routes[cveId] = () => new HttpResponseMessage(status);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var cveId = System.Web.HttpUtility.ParseQueryString(request.RequestUri!.Query)["cveId"] ?? string.Empty;
            return Task.FromResult(_routes.TryGetValue(cveId, out var responder)
                ? responder()
                : new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
