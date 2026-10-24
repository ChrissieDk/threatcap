using System.Net.Mail;
using System.Text.RegularExpressions;

namespace Threatwatch.Core.Identity;

/// <summary>
/// Email and display-name checks for account registration. Password complexity is
/// enforced by ASP.NET Core Identity using the same length constant.
/// </summary>
public static partial class AccountRules
{
    public const int MinPasswordLength = 12;
    public const int MaxPasswordLength = 128;
    public const int MaxDisplayNameLength = 80;
    public const int MaxEmailLength = 254;

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex EmailPattern();

    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        var value = email.Trim();
        if (value.Length > MaxEmailLength || value.Contains('\r') || value.Contains('\n'))
        {
            return false;
        }

        try
        {
            var parsed = new MailAddress(value);
            if (!string.Equals(parsed.Address, value, StringComparison.Ordinal))
            {
                return false;
            }
        }
        catch (FormatException)
        {
            return false;
        }

        return EmailPattern().IsMatch(value);
    }

    public static string NormalizeDisplayName(string? displayName, string email)
    {
        var value = string.IsNullOrWhiteSpace(displayName) ? email.Split('@')[0] : displayName.Trim();
        value = value.Replace("\r", "", StringComparison.Ordinal).Replace("\n", "", StringComparison.Ordinal).Trim();
        if (value.Length == 0)
        {
            value = "User";
        }

        return value.Length > MaxDisplayNameLength ? value[..MaxDisplayNameLength] : value;
    }
}
