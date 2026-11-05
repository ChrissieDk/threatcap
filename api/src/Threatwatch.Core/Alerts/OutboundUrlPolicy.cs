using System.Net;
using System.Net.Sockets;

namespace Threatwatch.Core.Alerts;

/// <summary>
/// SSRF guard for user-supplied webhook and ntfy URLs. Shape checks run when a channel is
/// saved; <see cref="IsPublicAddress"/> is re-checked at connect time by the sender so a
/// hostname that later resolves to an internal address (DNS rebinding) is still refused.
/// </summary>
public static class OutboundUrlPolicy
{
    public const int MaxUrlLength = 500;

    public static bool TryParse(string? raw, bool allowPrivate, out Uri uri, out string error)
    {
        uri = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(raw) || raw.Length > MaxUrlLength)
        {
            error = $"URL is required and must be at most {MaxUrlLength} characters.";
            return false;
        }

        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var parsed))
        {
            error = "URL is not valid.";
            return false;
        }

        var schemeOk = parsed.Scheme == Uri.UriSchemeHttps
            || (allowPrivate && parsed.Scheme == Uri.UriSchemeHttp);
        if (!schemeOk)
        {
            error = allowPrivate ? "URL must use http or https." : "URL must use https.";
            return false;
        }

        if (!string.IsNullOrEmpty(parsed.UserInfo))
        {
            error = "URL must not contain credentials.";
            return false;
        }

        if (!allowPrivate && IPAddress.TryParse(parsed.Host.Trim('[', ']'), out var literal) && !IsPublicAddress(literal))
        {
            error = "URL must not point to a private or local address.";
            return false;
        }

        if (!allowPrivate && (parsed.IsLoopback || parsed.Host.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
            || parsed.Host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
            || parsed.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))
        {
            error = "URL must not point to a private or local address.";
            return false;
        }

        uri = parsed;
        return true;
    }

    public static bool IsPublicAddress(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            return false;
        }

        var b = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            return !(b[0] == 0
                || b[0] == 10
                || (b[0] == 100 && b[1] is >= 64 and <= 127)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 198 && b[1] is 18 or 19)
                || b[0] >= 224);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return !(address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || address.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC); // fc00::/7 unique local
        }

        return false;
    }

    /// <summary>Resolves the host and requires every address to be public.</summary>
    public static async Task<bool> ResolvesPubliclyAsync(Uri uri, CancellationToken ct)
    {
        try
        {
            var host = uri.Host.Trim('[', ']');
            var addresses = IPAddress.TryParse(host, out var literal)
                ? [literal]
                : await Dns.GetHostAddressesAsync(host, ct);
            return addresses.Length > 0 && addresses.All(IsPublicAddress);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return false;
        }
    }
}
