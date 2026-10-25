using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class StatusPageDataSourceTests : IDisposable
{
    private readonly ServiceProvider _services;
    private readonly ThreatwatchDbContext _db;
    private readonly StubHandler _handler;
    private readonly StatusPageDataSource _source;

    public StatusPageDataSourceTests()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddDbContext<ThreatwatchDbContext>(options =>
            options.UseInMemoryDatabase(dbName));
        _services = services.BuildServiceProvider();
        _db = _services.GetRequiredService<ThreatwatchDbContext>();
        _handler = new StubHandler();
        var httpClient = new HttpClient(_handler);
        _source = new StatusPageDataSource(httpClient, NullLogger<StatusPageDataSource>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _services.Dispose();
    }

    [Fact]
    public async Task SyncUpsertsIncidentsAndIsIdempotent()
    {
        RespondAllOk(NpmJson("inc-1", "investigating", "major", resolved: false));

        var first = await SyncAsync();
        Assert.Equal(1, first.RecordsProcessed);
        var row = Assert.Single(_db.SecurityIncidents);
        Assert.Equal("npm:inc-1", row.ExternalId);
        Assert.Equal("npm registry outage", row.Title);
        Assert.Equal(IncidentStatus.Investigating, row.Status);
        Assert.Equal(IncidentType.Outage, row.Type);
        Assert.Equal(Ecosystem.Npm, row.Ecosystem);
        Assert.Null(row.ResolvedAt);

        RespondAllOk(NpmJson("inc-1", "resolved", "major", resolved: true));
        var second = await SyncAsync();
        Assert.Equal(1, second.RecordsProcessed);
        Assert.Equal(1, await _db.SecurityIncidents.CountAsync());
        await _db.Entry(row).ReloadAsync();
        Assert.Equal(IncidentStatus.Resolved, row.Status);
        Assert.NotNull(row.ResolvedAt);
    }

    [Fact]
    public async Task OneFailedFeedDoesNotBlockTheOthers()
    {
        foreach (var vendor in StatusPageMapper.Vendors)
        {
            if (vendor.Slug == "github")
            {
                _handler.RespondWithStatus(vendor.IncidentsUrl, HttpStatusCode.InternalServerError);
            }
            else
            {
                _handler.RespondWithJson(vendor.IncidentsUrl, EmptyJson());
            }
        }

        var result = await SyncAsync();
        Assert.Null(result.Error);
        Assert.Equal(0, result.RecordsProcessed);
    }

    private async Task<Threatwatch.Ingestion.Abstractions.IngestionResult> SyncAsync()
    {
        await using var scope = _services.CreateAsyncScope();
        return await _source.SyncAsync(scope, CancellationToken.None);
    }

    private void RespondAllOk(string npmJson)
    {
        foreach (var vendor in StatusPageMapper.Vendors)
        {
            _handler.RespondWithJson(
                vendor.IncidentsUrl,
                vendor.Slug == "npm" ? npmJson : EmptyJson());
        }
    }

    private static string EmptyJson() => """{"page":{"name":"x","url":"https://example.test"},"incidents":[]}""";

    private static string NpmJson(string id, string status, string impact, bool resolved) =>
        $$"""
        {
          "page": { "name": "npm", "url": "https://status.npmjs.org", "updated_at": "2026-10-25T12:00:00Z" },
          "incidents": [
            {
              "id": "{{id}}",
              "name": "npm registry outage",
              "status": "{{status}}",
              "impact": "{{impact}}",
              "shortlink": "https://stspg.io/{{id}}",
              "created_at": "2026-10-25T10:00:00Z",
              "started_at": "2026-10-25T10:00:00Z",
              "resolved_at": {{(resolved ? "\"2026-10-25T11:00:00Z\"" : "null")}},
              "incident_updates": [
                { "status": "{{status}}", "body": "Packages cannot be installed.", "created_at": "2026-10-25T10:00:00Z" }
              ]
            }
          ]
        }
        """;

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);

        public void RespondWithJson(string url, string json) =>
            _routes[url] = () => new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };

        public void RespondWithStatus(string url, HttpStatusCode status) =>
            _routes[url] = () => new HttpResponseMessage(status);

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = request.RequestUri?.ToString() ?? string.Empty;
            if (_routes.TryGetValue(url, out var responder))
            {
                return Task.FromResult(responder());
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
