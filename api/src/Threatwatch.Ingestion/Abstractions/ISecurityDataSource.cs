using Microsoft.Extensions.DependencyInjection;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Abstractions;

public record IngestionResult(int RecordsProcessed, string? NewWatermark, string? Error = null)
{
    public static IngestionResult Success(int records, string? watermark) => new(records, watermark);
    public static IngestionResult Failure(string error) => new(0, null, error);
}

public interface ISecurityDataSource
{
    string Name { get; }
    IngestionSource Source { get; }
    TimeSpan Interval { get; }
    Task<IngestionResult> SyncAsync(IServiceScope scope, CancellationToken ct);
}

public static class IngestionServiceCollectionExtensions
{
    /// <param name="attemptTimeout">
    /// Per-attempt budget. Leave null for small JSON feeds (10s attempt, 30s total).
    /// Pass a long value for multi-minute downloads such as OSV <c>all.zip</c>.
    /// <see cref="HttpClient.Timeout"/> is set slightly above the total request timeout.
    /// </param>
    public static IServiceCollection AddSecurityDataSource<T>(
        this IServiceCollection services,
        Uri baseAddress,
        TimeSpan? attemptTimeout = null)
        where T : class, ISecurityDataSource
    {
        var attempt = attemptTimeout ?? TimeSpan.FromSeconds(10);
        var total = attemptTimeout is null
            ? TimeSpan.FromSeconds(30)
            : attempt + TimeSpan.FromMinutes(5);

        services.AddHttpClient<T>(client =>
        {
            client.BaseAddress = baseAddress;
            client.DefaultRequestHeaders.UserAgent.ParseAdd("Threatwatch/1.0");
            client.Timeout = total + TimeSpan.FromMinutes(1);
        })
        .AddStandardResilienceHandler(options =>
        {
            options.Retry.MaxRetryAttempts = 3;
            options.Retry.Delay = TimeSpan.FromSeconds(2);
            options.Retry.BackoffType = Polly.DelayBackoffType.Exponential;
            options.Retry.UseJitter = true;
            options.AttemptTimeout.Timeout = attempt;
            options.TotalRequestTimeout.Timeout = total;
            // Sampling duration must be at least twice the attempt timeout.
            options.CircuitBreaker.SamplingDuration = attempt * 2;
        });

        // AddHttpClient<T> already registers T as transient with the configured HttpClient;
        // only the interface mapping is needed here.
        services.AddTransient<ISecurityDataSource>(sp => sp.GetRequiredService<T>());
        return services;
    }
}
