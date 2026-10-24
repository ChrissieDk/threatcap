using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Identity;

namespace Threatwatch.Api.Controllers;

[ApiController]
[Route("api/v1/auth")]
[EnableRateLimiting("auth")]
public class AuthController(UserManager<UserAccount> users, SignInManager<UserAccount> signIn) : ControllerBase
{
    public const string BrowserHeader = "X-Threatwatch-Request";

    private static readonly string DummyHash = new PasswordHasher<UserAccount>().HashPassword(
        new UserAccount { DisplayName = "unused", UserName = "unused@example.com" },
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterRequest? request)
    {
        if (!HasBrowserHeader())
        {
            return MissingHeader();
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
        return Ok(ToPayload(user));
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

    private static object ToPayload(UserAccount user) => new
    {
        user.Id,
        user.Email,
        user.DisplayName,
    };

    public sealed record RegisterRequest(string? Email, string? Password, string? DisplayName);

    public sealed record LoginRequest(string? Email, string? Password);
}
