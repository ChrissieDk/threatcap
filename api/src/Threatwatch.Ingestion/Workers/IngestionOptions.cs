namespace Threatwatch.Ingestion.Workers;

public class IngestionOptions
{
    /// <summary>
    /// When true (default) the worker starts syncing on boot. When false it stays idle
    /// until a signed-in user triggers a sync (login, register, or Refresh).
    /// </summary>
    public bool AutoStart { get; set; } = true;

    /// <summary>How often the worker checks for providers that are due.</summary>
    public int PollSeconds { get; set; } = 30;
}
