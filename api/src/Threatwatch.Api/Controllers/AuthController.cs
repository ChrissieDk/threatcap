using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Alerts;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Identity;
using Threatwatch.Ingestion.Alerts;
using Threatwatch.Ingestion.Workers;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
[EnableRateLimiting("auth")]
public class AuthController(
    UserManager<UserAccount> users,
    SignInManager<UserAccount> signIn,
    IngestionRunner ingestion,
    SmtpMailer mailer,
    IMemoryCache cache,
    IOptions<AlertOptions> alertOptions,
    IOptions<RegistrationOptions> registration,
    ILogger<AuthController> logger) : ControllerBase
{
    private static readonly TimeSpan VerificationResendCooldown = TimeSpan.FromSeconds(60);

    public const string BrowserHeader = "X-Threatwatch-Request";

    private static readonly string DummyHash = new PasswordHasher<UserAccount>().HashPassword(
        new UserAccount { DisplayName = "unused", UserName = "unused@example.com" },
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    [HttpGet("registration")]
    [AllowAnonymous]
    public IActionResult RegistrationStatus() => Ok(new
    {
        open = registration.Value.RegistrationOpen,
        inviteRequired = registration.Value.RegistrationOpen && registration.Value.HasInviteCode,
    });

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest? request)
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
        }

        if (!registration.Value.RegistrationOpen)
        {
            return ApiError.ToResult(
                new ApiError("registration_closed", "Sign-up is currently closed."), StatusCodes.Status403Forbidden);
        }

        if (registration.Value.HasInviteCode && !registration.Value.InviteMatches(request?.InviteCode))
        {
            return ApiError.ToResult(
                new ApiError("invalid_invite", "That invite code is not valid."), StatusCodes.Status403Forbidden);
        }

        if (request is null)
        {
            return ApiError.ToResult(ApiError.Validation("Request body is required."), StatusCodes.Status400BadRequest);
        }

        var email = request.Email?.Trim() ?? "";
        var password = request.Password ?? "";
        if (!AccountRules.IsValidEmail(email))
        {
            return ApiError.ToResult(ApiError.Validation("Enter a valid email address."), StatusCodes.Status400BadRequest);
        }

        if (password.Length == 0 || password.Length > AccountRules.MaxPasswordLength)
        {
            return ApiError.ToResult(
                ApiError.Validation($"Password must be {AccountRules.MinPasswordLength}–{AccountRules.MaxPasswordLength} characters and include uppercase, lowercase, a number, and a symbol."),
                StatusCodes.Status400BadRequest);
        }

        var user = new UserAccount
        {
            Id = Guid.NewGuid(),
            UserName = email,
            Email = email,
            DisplayName = AccountRules.NormalizeDisplayName(request.DisplayName, email),
            CreatedAt = DateTimeOffset.UtcNow,
            LockoutEnabled = true,
        };

        var result = await users.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            if (result.Errors.Any(error => error.Code is "DuplicateEmail" or "DuplicateUserName"))
            {
                return ApiError.ToResult(
                    new ApiError("conflict", "An account with this email already exists."),
                    StatusCodes.Status409Conflict);
            }

            return ApiError.ToResult(
                ApiError.Validation(string.Join(" ", result.Errors.Select(error => error.Description))),
                StatusCodes.Status400BadRequest);
        }

        await signIn.SignInAsync(user, isPersistent: true);
        ingestion.RequestSync();
        if (mailer.IsConfigured)
        {
            // Best effort: a mail outage must not block registration; users can resend later.
            await TrySendVerificationAsync(user, HttpContext.RequestAborted);
        }

        return Ok(ToPayload(user));
    }

    [HttpPost("verify-email/send")]
    public async Task<IActionResult> SendVerification()
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
        }

        var user = await users.GetUserAsync(User);
        if (user is null)
        {
            return ApiError.ToResult(new ApiError("unauthorized", "Sign in required."), StatusCodes.Status401Unauthorized);
        }

        if (user.EmailConfirmed)
        {
            return Ok(new { alreadyVerified = true });
        }

        if (!mailer.IsConfigured)
        {
            return ApiError.ToResult(
                ApiError.Validation("Email is not configured on this server."), StatusCodes.Status400BadRequest);
        }

        if (!cache.TryGetValue(CooldownKey(user.Id), out _))
        {
            cache.Set(CooldownKey(user.Id), true, VerificationResendCooldown);
            var sendError = await TrySendVerificationAsync(user, HttpContext.RequestAborted);
            if (sendError is not null)
            {
                cache.Remove(CooldownKey(user.Id));
                return ApiError.ToResult(
                    new ApiError("unavailable", sendError),
                    StatusCodes.Status502BadGateway);
            }
        }

        return Ok(new { sent = true });
    }

    [HttpPost("verify-email/confirm")]
    [AllowAnonymous]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest? request)
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
        }

        // One generic failure for every problem so the endpoint reveals nothing about accounts.
        var failure = ApiError.ToResult(
            ApiError.Validation("This verification link is invalid or has expired."), StatusCodes.Status400BadRequest);
        if (string.IsNullOrWhiteSpace(request?.UserId) || string.IsNullOrWhiteSpace(request.Token) || request.Token.Length > 2000)
        {
            return failure;
        }

        var user = await users.FindByIdAsync(request.UserId);
        if (user is null)
        {
            return failure;
        }

        string token;
        try
        {
            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
        }
        catch (FormatException)
        {
            return failure;
        }

        var result = await users.ConfirmEmailAsync(user, token);
        return result.Succeeded ? Ok(new { verified = true }) : failure;
    }

    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login([FromBody] LoginRequest? request)
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
        }

        var email = request?.Email?.Trim() ?? "";
        var password = request?.Password ?? "";
        if (!AccountRules.IsValidEmail(email) || password.Length == 0 || password.Length > AccountRules.MaxPasswordLength)
        {
            BurnPasswordCheck(password);
            return InvalidCredentials();
        }

        var user = await users.FindByEmailAsync(email);
        if (user is null)
        {
            BurnPasswordCheck(password);
            return InvalidCredentials();
        }

        var result = await signIn.PasswordSignInAsync(user, password, isPersistent: true, lockoutOnFailure: true);
        if (result.IsLockedOut)
        {
            return ApiError.ToResult(
                new ApiError("locked", "This account is temporarily locked. Try again in 15 minutes."),
                StatusCodes.Status423Locked);
        }

        if (!result.Succeeded)
        {
            return InvalidCredentials();
        }

        ingestion.RequestSync();
        return Ok(ToPayload(user));
    }

    [HttpPost("logout")]
    [AllowAnonymous]
    public async Task<IActionResult> Logout()
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
        }

        await signIn.SignOutAsync();
        return NoContent();
    }

    [HttpGet("me")]
    public async Task<IActionResult> Me()
    {
        var user = await users.GetUserAsync(User);
        if (user is null)
        {
            return ApiError.ToResult(
                new ApiError("unauthorized", "Sign in required."),
                StatusCodes.Status401Unauthorized);
        }

        return Ok(ToPayload(user));
    }

    private static string CooldownKey(Guid userId) => $"verify-email:{userId}";

    private async Task<string?> TrySendVerificationAsync(UserAccount user, CancellationToken ct)
    {
        try
        {
            var raw = await users.GenerateEmailConfirmationTokenAsync(user);
            var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(raw));
            var link = $"{alertOptions.Value.WebBaseUrl.TrimEnd('/')}/verify-email?uid={user.Id}&token={token}";
            await mailer.SendAsync(
                user.Email!,
                "Verify your Threatwatch email",
                $"Hi {user.DisplayName},\n\nConfirm your email address to receive Threatwatch alerts by email:\n\n{link}\n\nThe link expires in 24 hours. If you did not create this account you can ignore this message.",
                ct);
            return null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Could not send verification email for user {UserId}.", user.Id);
            return ex is AlertSendException ? ex.Message : "Could not send the verification email.";
        }
    }

    private bool HasBrowserHeader() =>
        Request.Headers.TryGetValue(BrowserHeader, out var value) && value == "1";

    private void BurnPasswordCheck(string password)
    {
        var attempt = password.Length > AccountRules.MaxPasswordLength
            ? password[..AccountRules.MaxPasswordLength]
            : password.Length == 0 ? " " : password;
        users.PasswordHasher.VerifyHashedPassword(
            new UserAccount { DisplayName = "unused", UserName = "unused@example.com" },
            DummyHash,
            attempt);
    }

    private IActionResult MissingHeader() =>
        ApiError.ToResult(ApiError.Validation("Missing X-Threatwatch-Request header."), StatusCodes.Status400BadRequest);

    private IActionResult InvalidCredentials() =>
        ApiError.ToResult(new ApiError("unauthorized", "Invalid email or password."), StatusCodes.Status401Unauthorized);

    private object ToPayload(UserAccount user) => new
    {
        user.Id,
        user.Email,
        user.DisplayName,
        user.EmailConfirmed,
        EmailVerificationAvailable = mailer.IsConfigured,
    };

    public sealed record RegisterRequest(string? Email, string? Password, string? DisplayName, string? InviteCode = null);

    public sealed record LoginRequest(string? Email, string? Password);

    public sealed record ConfirmEmailRequest(string? UserId, string? Token);
}
