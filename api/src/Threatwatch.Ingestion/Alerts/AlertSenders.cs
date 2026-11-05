using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Ingestion.Alerts;

public record AlertMessageItem(string Title, string? Summary, string? Url);

public record AlertMessage(string Subject, IReadOnlyList<AlertMessageItem> Items, int MoreCount, string? FooterUrl)
{
    public string ToPlainText()
    {
        var sb = new StringBuilder();
        sb.AppendLine(Subject);
        foreach (var item in Items)
        {
            sb.AppendLine().Append("• ").AppendLine(item.Title);
            if (!string.IsNullOrEmpty(item.Summary)) sb.Append("  ").AppendLine(item.Summary);
            if (!string.IsNullOrEmpty(item.Url)) sb.Append("  ").AppendLine(item.Url);
        }

        if (MoreCount > 0)
        {
            sb.AppendLine().AppendLine($"…and {MoreCount} more.");
        }

        if (!string.IsNullOrEmpty(FooterUrl))
        {
            sb.AppendLine().Append("Manage alerts: ").AppendLine(FooterUrl);
        }

        return sb.ToString().TrimEnd();
    }
}

/// <summary>Thrown by senders; <see cref="Message"/> is safe to show to the user (no secrets).</summary>
public class AlertSendException(string message, bool permanent = false) : Exception(message)
{
    /// <summary>True when retrying can never succeed (e.g. an expired push subscription).</summary>
    public bool Permanent { get; } = permanent;
}

public interface IAlertSender
{
    AlertChannelType Type { get; }

    Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct);
}

public static class AlertHttp
{
    public const string ClientName = "alert-outbound";

    /// <summary>
    /// Handler that resolves DNS itself and refuses non-public addresses at connect time
    /// (defeats DNS rebinding), never follows redirects and ignores system proxies.
    /// </summary>
    public static SocketsHttpHandler CreateHandler(bool allowPrivate) => new()
    {
        AllowAutoRedirect = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(8),
        ConnectCallback = async (context, ct) =>
        {
            var addresses = await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, ct);
            if (addresses.Length == 0 || (!allowPrivate && !addresses.All(OutboundUrlPolicy.IsPublicAddress)))
            {
                throw new HttpRequestException("Target resolves to a blocked address.");
            }

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        },
    };

    public static async Task PostAsync(HttpClient http, HttpRequestMessage request, CancellationToken ct)
    {
        try
        {
            using var response = await http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new AlertSendException($"Destination responded with HTTP {(int)response.StatusCode}.");
            }
        }
        catch (AlertSendException)
        {
            throw;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new AlertSendException("Destination timed out.");
        }
        catch (HttpRequestException)
        {
            throw new AlertSendException("Could not reach destination.");
        }
    }
}

public sealed class WebhookAlertSender(IHttpClientFactory httpFactory) : IAlertSender
{
    public AlertChannelType Type => AlertChannelType.Webhook;

    public async Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct)
    {
        if (target is null) throw new AlertSendException("Channel has no destination.");

        var text = message.ToPlainText();
        if (text.Length > 1900) text = text[..1899] + "…";

        // "text" is read by Slack/Mattermost/Teams-style hooks, "content" by Discord; the
        // structured "items" are for custom receivers.
        using var request = new HttpRequestMessage(HttpMethod.Post, target)
        {
            Content = JsonContent.Create(new
            {
                text,
                content = text,
                subject = message.Subject,
                items = message.Items.Select(i => new { title = i.Title, summary = i.Summary, url = i.Url }),
                more = message.MoreCount,
            }),
        };
        await AlertHttp.PostAsync(httpFactory.CreateClient(AlertHttp.ClientName), request, ct);
    }
}

public sealed class NtfyAlertSender(IHttpClientFactory httpFactory) : IAlertSender
{
    public AlertChannelType Type => AlertChannelType.Ntfy;

    public async Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct)
    {
        if (target is null) throw new AlertSendException("Channel has no destination.");

        using var request = new HttpRequestMessage(HttpMethod.Post, target)
        {
            Content = new StringContent(message.ToPlainText(), Encoding.UTF8, "text/plain"),
        };
        // Header values must be ASCII; the full title is in the body.
        request.Headers.TryAddWithoutValidation("Title", AsciiHeader(message.Subject));
        request.Headers.TryAddWithoutValidation("Tags", "rotating_light");
        var first = message.Items.FirstOrDefault()?.Url;
        if (first is not null && Uri.TryCreate(first, UriKind.Absolute, out _))
        {
            request.Headers.TryAddWithoutValidation("Click", AsciiHeader(first));
        }

        await AlertHttp.PostAsync(httpFactory.CreateClient(AlertHttp.ClientName), request, ct);
    }

    private static string AsciiHeader(string value) =>
        new(value.Where(c => c is >= ' ' and <= '~').Take(200).ToArray());
}

public class SmtpOptions
{
    public string? Host { get; set; }
    public int Port { get; set; } = 587;
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? From { get; set; }
    public string FromName { get; set; } = "Threatwatch";

    /// <summary>StartTls (default, port 587), Ssl (port 465) or None (local dev, e.g. Mailpit).</summary>
    public string Security { get; set; } = "StartTls";

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Host) && !string.IsNullOrWhiteSpace(From);
}

/// <summary>Sends plain-text mail through the configured SMTP server (alerts and verification).</summary>
public class SmtpMailer(IOptions<SmtpOptions> options, ILogger<SmtpMailer> logger, IHostEnvironment? environment = null)
{
    public bool IsConfigured => options.Value.IsConfigured;

    public async Task SendAsync(string to, string subject, string body, CancellationToken ct)
    {
        var smtp = options.Value;
        if (!smtp.IsConfigured) throw new AlertSendException("Email is not configured on this server.");
        if (string.IsNullOrWhiteSpace(to)) throw new AlertSendException("Account has no email address.");

        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(smtp.FromName, smtp.From));
        mime.To.Add(MailboxAddress.Parse(to));
        mime.Subject = subject;
        mime.Body = new TextPart("plain") { Text = body };

        var secure = smtp.Security.ToLowerInvariant() switch
        {
            "ssl" => SecureSocketOptions.SslOnConnect,
            "none" => SecureSocketOptions.None,
            _ => SecureSocketOptions.StartTls,
        };

        try
        {
            using var client = new SmtpClient { Timeout = 15_000 };
            await client.ConnectAsync(smtp.Host, smtp.Port, secure, ct);
            if (!string.IsNullOrEmpty(smtp.Username))
            {
                await client.AuthenticateAsync(smtp.Username, smtp.Password ?? string.Empty, ct);
            }

            await client.SendAsync(mime, ct);
            await client.DisconnectAsync(true, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not AlertSendException)
        {
            // Operator-facing detail goes to the log only; users get a generic message.
            logger.LogError(ex, "SMTP send to {Host}:{Port} failed ({Security}).", smtp.Host, smtp.Port, smtp.Security);
            var detail = environment?.IsDevelopment() == true ? $" ({ex.GetType().Name}: {ex.Message})" : string.Empty;
            throw new AlertSendException("Could not send email via the configured SMTP server." + detail);
        }
    }
}

public sealed class EmailAlertSender(SmtpMailer mailer) : IAlertSender
{
    public AlertChannelType Type => AlertChannelType.Email;

    public Task SendAsync(AlertChannel channel, string? target, string? recipientEmail, AlertMessage message, CancellationToken ct) =>
        mailer.SendAsync(recipientEmail ?? string.Empty, message.Subject, message.ToPlainText(), ct);
}
