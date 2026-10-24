using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Threatwatch.Api.Infrastructure;
using Threatwatch.Core.Data;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Identity;
using Threatwatch.Core.Services;
using Threatwatch.Ingestion.Abstractions;
using Threatwatch.Ingestion.Providers;
using Threatwatch.Ingestion.Workers;

var builder = WebApplication.CreateBuilder(args);
builder.Configuration.AddJsonFile(
    $"appsettings.{builder.Environment.EnvironmentName}.local.json",
    optional: true,
    reloadOnChange: true);

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' is not configured.");

builder.Services.AddDbContext<ThreatwatchDbContext>(options =>
    options.UseNpgsql(connectionString));

var apiKey = builder.Configuration["Auth:ApiKey"];
if (string.IsNullOrWhiteSpace(apiKey) || apiKey.Length < 16)
{
    throw new InvalidOperationException(
        "Auth:ApiKey must be a secret of at least 16 characters. Set Auth__ApiKey or add appsettings.Development.local.json.");
}

var keysDir = new DirectoryInfo(Path.Combine(builder.Environment.ContentRootPath, "data-protection-keys"));
Directory.CreateDirectory(keysDir.FullName);
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(
        keysDir.FullName,
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
}

builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(keysDir)
    .SetApplicationName("Threatwatch");

builder.Services.AddIdentity<UserAccount, IdentityRole<Guid>>(options =>
    {
        options.User.RequireUniqueEmail = true;
        options.SignIn.RequireConfirmedEmail = false;
        options.Password.RequiredLength = AccountRules.MinPasswordLength;
        options.Password.RequiredUniqueChars = 4;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = true;
        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<ThreatwatchDbContext>();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.Name = "threatwatch.session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
        ? CookieSecurePolicy.SameAsRequest
        : CookieSecurePolicy.Always;
    options.SlidingExpiration = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(7);
    options.Events.OnRedirectToLogin = context =>
        WriteAuthStatus(context.Response, StatusCodes.Status401Unauthorized, "unauthorized", "Sign in required.");
    options.Events.OnRedirectToAccessDenied = context =>
        WriteAuthStatus(context.Response, StatusCodes.Status403Forbidden, "forbidden", "Access denied.");
});

builder.Services.AddAuthorization();

builder.Services.AddControllers(options =>
    {
        options.Filters.Add(new AuthorizeFilter());
    })
    .AddJsonOptions(options =>
        options.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new() { Title = "Threatwatch API", Version = "v1" });
    options.UseInlineDefinitionsForEnums();
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = new { code = "rate_limited", message = "Too many requests. Try again in a minute." },
        }, token);
    };
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(ClientPartitionKey(context), _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 300,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
    options.AddPolicy("auth", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter($"auth:{ClientPartitionKey(httpContext)}", _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
    options.AddPolicy("writes", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter($"writes:{ClientPartitionKey(httpContext)}", _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 60,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));
});

builder.Services.AddHealthChecks()
    .AddDbContextCheck<ThreatwatchDbContext>("database", failureStatus: HealthStatus.Unhealthy);

// Query services
builder.Services.AddScoped<DashboardService>();
builder.Services.AddScoped<VulnerabilityQueryService>();
builder.Services.AddScoped<TechnologyQueryService>();
builder.Services.AddScoped<FollowService>();

// Ingestion
builder.Services.AddScoped<VulnerabilityUpserter>();
const string FrontendOrigin = "http://localhost:3000";
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins(FrontendOrigin)
            .AllowAnyHeader()
            .AllowAnyMethod());
});

builder.Services.AddSecurityDataSource<CisaKevDataSource>(new Uri("https://www.cisa.gov/"));
builder.Services.AddSecurityDataSource<OsvDataSource>(
    new Uri("https://storage.googleapis.com/"),
    attemptTimeout: TimeSpan.FromMinutes(2));
builder.Services.Configure<OsvOptions>(builder.Configuration.GetSection("Osv"));
builder.Services.AddHostedService<IngestionWorker>();
builder.Services.AddHostedService<OsvBackfillService>();
builder.Services.AddHostedService<DbSeederHostedService>();

var app = builder.Build();

app.UseRouting();
app.UseCors();
app.UseRateLimiter();
app.UseMiddleware<ApiKeyMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger(options => options.RouteTemplate = "openapi/{documentName}.json");
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/openapi/v1.json", "Threatwatch API v1");
        options.RoutePrefix = "openapi";
    });
}

app.MapHealthChecks("/health", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            status = report.Status.ToString(),
            checks = report.Entries.Select(e => new { name = e.Key, status = e.Value.Status.ToString() }),
        });
    },
});

app.MapControllers();

app.Run();

static Task WriteAuthStatus(HttpResponse response, int status, string code, string message)
{
    response.StatusCode = status;
    return response.WriteAsJsonAsync(new { error = new { code, message } });
}

static string ClientPartitionKey(HttpContext context)
{
    var remote = context.Connection.RemoteIpAddress;
    if (remote is not null && IPAddress.IsLoopback(remote)
        && context.Request.Headers.TryGetValue("X-Forwarded-For", out var forwarded))
    {
        var client = forwarded.ToString().Split(',')[0].Trim();
        if (client.Length > 0)
        {
            return client;
        }
    }

    return remote?.ToString() ?? "unknown";
}

public partial class Program;
