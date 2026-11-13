using System.Security.Cryptography;
using System.Text;

namespace Threatwatch.Core.Identity;

/// <summary>Bound to the <c>Auth</c> section: <c>Auth__RegistrationOpen</c> and <c>Auth__InviteCode</c>.</summary>
public class RegistrationOptions
{
    /// <summary>When false nobody can create an account.</summary>
    public bool RegistrationOpen { get; set; } = true;

    /// <summary>When set, sign-up requires this code.</summary>
    public string? InviteCode { get; set; }

    public bool HasInviteCode => !string.IsNullOrWhiteSpace(InviteCode);

    public bool InviteMatches(string? supplied)
    {
        if (!HasInviteCode) return true;
        var expected = SHA256.HashData(Encoding.UTF8.GetBytes(InviteCode!.Trim()));
        var actual = SHA256.HashData(Encoding.UTF8.GetBytes((supplied ?? "").Trim()));
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }
}
