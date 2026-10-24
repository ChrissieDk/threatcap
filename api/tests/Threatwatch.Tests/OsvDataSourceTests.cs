using System.IO.Compression;
using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Threatwatch.Core.Data;
using Threatwatch.Core.Enums;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Providers;

namespace Threatwatch.Tests;

public class OsvDataSourceTests : IDisposable
{
    private const string Watermark = "2026-10-01T00:00:00+00:00";
    private const string NewerModified = "2026-10-20T12:00:00Z";
    private const string OlderModified = "2026-09-15T12:00:00Z";

    private readonly ServiceProvider _services;
    private readonly ThreatwatchDbContext _db;
    private readonly StubHandler _handler;
    private readonly OsvDataSource _source;

    public OsvDataSourceTests()
    {
        var dbName = Guid.NewGuid().ToString();
        var services = new ServiceCollection();
        services.AddDbContext<ThreatwatchDbContext>(options => options.UseInMemoryDatabase(dbName));
        services.AddScoped<VulnerabilityUpserter>(sp =>
            new VulnerabilityUpserter(
                sp.GetRequiredService<ThreatwatchDbContext>(),
                NullLogger<VulnerabilityUpserter>.Instance));
        _services = services.BuildServiceProvider();

        _db = _services.GetRequiredService<ThreatwatchDbContext>();
        _db.IngestionStates.Add(new Threatwatch.Core.Entities.IngestionState
        {
            Id = Guid.NewGuid(),
            Source = IngestionSource.Osv,
            Watermark = Watermark,
        });
        _db.SaveChanges();

        _handler = new StubHandler();
        var httpClient = new HttpClient(_handler) { BaseAddress = new Uri("https://storage.googleapis.com/") };
        _source = new OsvDataSource(
            httpClient,
            Options.Create(new OsvOptions { Ecosystems = ["npm"] }),
            _services.GetRequiredService<IServiceScopeFactory>(),
            NullLogger<OsvDataSource>.Instance);
    }

    public void Dispose()
    {
        _db.Dispose();
        _services.Dispose();
    }

    [Fact]
    public async Task ZipRecordsNewerThanWatermarkAreUpserted_AndOlderOnesAreSkipped()
    {
        var zip = BuildZip(
            ("GHSA-old.json", RecordJson("GHSA-old-xxxx-yyyy", OlderModified)),
            ("GHSA-new.json", RecordJson("GHSA-new-xxxx-yyyy", NewerModified)));
        _handler.RespondWithBytes("/osv-vulnerabilities/npm/all.zip", zip);

        var result = await SyncAsync();

        Assert.Equal(1, result.RecordsProcessed);
        Assert.Equal(NewerModified.ToDateTimeOffset().ToString("O"), result.NewWatermark);
        var vuln = Assert.Single(_db.Vulnerabilities);
        Assert.Equal("GHSA-new-xxxx-yyyy", vuln.CanonicalId);
    }

    [Fact]
    public async Task ZipRecordsOutsideRetentionAreSkipped()
    {
        var stale = "2026-01-01T00:00:00Z";
        var zip = BuildZip(("GHSA-stale.json", RecordJson("GHSA-stale-xxxx-yyyy", stale)));
        _handler.RespondWithBytes("/osv-vulnerabilities/npm/all.zip", zip);

        var result = await SyncAsync();

        Assert.Equal(0, result.RecordsProcessed);
        Assert.Empty(_db.Vulnerabilities);
    }

    [Fact]
    public async Task FallsBackToListingAndPerRecordDownloadWhenAllZipIsMissing()
    {
        _handler.RespondWithStatus("/osv-vulnerabilities/npm/all.zip", HttpStatusCode.NotFound);
        _handler.RespondWithJson(
            "/storage/v1/b/osv-vulnerabilities/o",
            """{"items":[{"name":"npm/GHSA-new-xxxx-yyyy.json","updated":"2026-10-21T00:00:00Z"}]}""");
        _handler.RespondWithJson(
            "/osv-vulnerabilities/npm/GHSA-new-xxxx-yyyy.json",
            RecordJson("GHSA-new-xxxx-yyyy", NewerModified));

        var result = await SyncAsync();

        Assert.Equal(1, result.RecordsProcessed);
        var vuln = Assert.Single(_db.Vulnerabilities);
        Assert.Equal("GHSA-new-xxxx-yyyy", vuln.CanonicalId);
    }

    private async Task<IngestionResult> SyncAsync()
    {
        await using var scope = _services.GetRequiredService<IServiceScopeFactory>().CreateAsyncScope();
        return await _source.SyncAsync(scope, CancellationToken.None);
    }

    private static string RecordJson(string id, string modified) =>
        $$"""{"id":"{{id}}","summary":"Test advisory","modified":"{{modified}}","published":"2026-09-01T00:00:00Z"}""";

    private static byte[] BuildZip(params (string Name, string Json)[] entries)
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, json) in entries)
            {
                var entry = archive.CreateEntry(name);
                using var writer = new StreamWriter(entry.Open(), Encoding.UTF8);
                writer.Write(json);
            }
        }

        return stream.ToArray();
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly Dictionary<string, Func<HttpResponseMessage>> _routes = new(StringComparer.Ordinal);

        public void RespondWithBytes(string path, byte[] bytes) =>
            _routes[path] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };

        public void RespondWithJson(string path, string json) =>
            _routes[path] = () => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

        public void RespondWithStatus(string path, HttpStatusCode status) =>
            _routes[path] = () => new HttpResponseMessage(status);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (_routes.TryGetValue(path, out var responder))
            {
                return Task.FromResult(responder());
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}

internal static class StringExtensions
{
    public static DateTimeOffset ToDateTimeOffset(this string value) =>
        OsvRecord.ParseRfc3339(value)!.Value;
}
