namespace Threatwatch.Core.Alerts;

public class AlertOptions
{
    public const int MaxChannelsPerUser = 5;

    /// <summary>Public base URL of the web app, used to build links inside alerts.</summary>
    public string WebBaseUrl { get; set; } = "http://localhost:3000";

    /// <summary>
    /// Allow webhook/ntfy targets on private or loopback addresses and over plain HTTP.
    /// Off by default (SSRF protection); turn on for a self-hosted ntfy on a trusted LAN.
    /// </summary>
    public bool AllowPrivateTargets { get; set; }

    /// <summary>ntfy server used when a user picks one-click phone alerts.</summary>
    public string NtfyServerUrl { get; set; } = "https://ntfy.sh";

    /// <summary>Contact for push services (a mailto: or https: URL). Defaults from WebBaseUrl.</summary>
    public string? PushSubject { get; set; }

    /// <summary>How often the dispatcher looks for new matches and pending deliveries.</summary>
    public int PollSeconds { get; set; } = 60;

    /// <summary>Items older than this are never alerted on, even for brand-new channels.</summary>
    public int LookbackDays { get; set; } = 3;

    /// <summary>Most items listed in one message; the rest are summarized as "and N more".</summary>
    public int MaxItemsPerMessage { get; set; } = 10;
}
