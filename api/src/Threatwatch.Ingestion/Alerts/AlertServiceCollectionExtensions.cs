using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Threatwatch.Core.Alerts;

namespace Threatwatch.Ingestion.Alerts;

public static class AlertServiceCollectionExtensions
{
    public static IServiceCollection AddAlerts(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AlertOptions>(configuration.GetSection("Alerts"));
        services.Configure<SmtpOptions>(configuration.GetSection("Smtp"));

        var allowPrivate = configuration.GetValue<bool>("Alerts:AllowPrivateTargets");
        services.AddHttpClient(AlertHttp.ClientName, client => client.Timeout = TimeSpan.FromSeconds(15))
            .ConfigurePrimaryHttpMessageHandler(() => AlertHttp.CreateHandler(allowPrivate));

        services.AddSingleton<SmtpMailer>();
        services.AddScoped<AlertService>();
        services.AddScoped<AlertDispatcher>();
        services.AddSingleton<IAlertSender, WebhookAlertSender>();
        services.AddSingleton<IAlertSender, NtfyAlertSender>();
        services.AddSingleton<IAlertSender, EmailAlertSender>();
        services.AddSingleton<VapidKeyStore>();
        services.AddSingleton<IAlertSender, BrowserPushAlertSender>();
        services.AddHostedService<AlertWorker>();
        return services;
    }
}
