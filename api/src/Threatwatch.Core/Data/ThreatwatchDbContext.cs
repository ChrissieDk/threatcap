using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Identity;

namespace Threatwatch.Core.Data;

public class ThreatwatchDbContext(DbContextOptions<ThreatwatchDbContext> options)
    : IdentityDbContext<UserAccount, IdentityRole<Guid>, Guid>(options)
{
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<VulnerabilityAlias> VulnerabilityAliases => Set<VulnerabilityAlias>();
    public DbSet<AffectedPackage> AffectedPackages => Set<AffectedPackage>();
    public DbSet<Technology> Technologies => Set<Technology>();
    public DbSet<UserFollow> UserFollows => Set<UserFollow>();
    public DbSet<SourceReference> SourceReferences => Set<SourceReference>();
    public DbSet<SecurityIncident> SecurityIncidents => Set<SecurityIncident>();
    public DbSet<VulnerabilityEvent> VulnerabilityEvents => Set<VulnerabilityEvent>();
    public DbSet<IngestionState> IngestionStates => Set<IngestionState>();

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        NormalizeDateTimeOffsetsToUtc();
        return base.SaveChangesAsync(cancellationToken);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        NormalizeDateTimeOffsetsToUtc();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    /// <summary>
    /// PostgreSQL 'timestamp with time zone' only accepts offset 0. Source feeds may
    /// yield DateTimeOffset values with local/feed offsets; convert everything to UTC
    /// before persisting so ingestion never fails on offset mismatches. Boxing means a
    /// DateTimeOffset? with a value already matches the non-nullable pattern below.
    /// </summary>
    private void NormalizeDateTimeOffsetsToUtc()
    {
        foreach (var entry in ChangeTracker.Entries())
        {
            foreach (var property in entry.Properties)
            {
                if (property.CurrentValue is DateTimeOffset dto && dto.Offset != TimeSpan.Zero)
                {
                    property.CurrentValue = dto.ToUniversalTime();
                }
            }
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.Entity<UserAccount>().ToTable("Users");
        modelBuilder.Entity<IdentityRole<Guid>>().ToTable("Roles");
        modelBuilder.Entity<IdentityUserRole<Guid>>().ToTable("UserRoles");
        modelBuilder.Entity<IdentityUserClaim<Guid>>().ToTable("UserClaims");
        modelBuilder.Entity<IdentityUserLogin<Guid>>().ToTable("UserLogins");
        modelBuilder.Entity<IdentityUserToken<Guid>>().ToTable("UserTokens");
        modelBuilder.Entity<IdentityRoleClaim<Guid>>().ToTable("RoleClaims");
        modelBuilder.Entity<Vulnerability>(b =>
        {
            b.HasIndex(x => x.CanonicalId).IsUnique();
            b.HasIndex(x => x.PublishedAt);
            b.HasIndex(x => x.ModifiedAt);
            b.HasIndex(x => x.Severity);
            b.HasIndex(x => x.IsKnownExploited);
            b.Property(x => x.Severity).HasConversion<string>();
        });

        modelBuilder.Entity<VulnerabilityAlias>(b =>
        {
            b.HasIndex(x => x.Alias).IsUnique();
            b.HasOne(x => x.Vulnerability)
                .WithMany(v => v.Aliases)
                .HasForeignKey(x => x.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);
            b.Property(x => x.AliasType).HasConversion<string>();
        });

        modelBuilder.Entity<AffectedPackage>(b =>
        {
            b.HasIndex(x => new { x.VulnerabilityId, x.Ecosystem, x.PackageName }).IsUnique();
            b.HasIndex(x => new { x.Ecosystem, x.PackageName });
            b.HasOne(x => x.Vulnerability)
                .WithMany(v => v.AffectedPackages)
                .HasForeignKey(x => x.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);
            b.Property(x => x.Ecosystem).HasConversion<string>();
            b.Property(x => x.AffectedRanges).HasColumnType("jsonb");
            b.Property(x => x.FixedVersions).HasColumnType("text[]");
        });

        modelBuilder.Entity<Technology>(b =>
        {
            b.HasIndex(x => x.Slug).IsUnique();
            b.Property(x => x.Type).HasConversion<string>();
            b.Property(x => x.Ecosystem).HasConversion<string>();
            b.Property(x => x.Aliases).HasColumnType("text[]");
            b.Property(x => x.MatchingRules).HasColumnType("jsonb");
        });

        modelBuilder.Entity<UserAccount>(b =>
        {
            b.HasIndex(x => x.ExternalId).IsUnique();
            b.Property(x => x.ExternalId).IsRequired(false);
            b.Property(x => x.DisplayName).HasMaxLength(AccountRules.MaxDisplayNameLength);
            b.HasIndex(x => x.NormalizedEmail).IsUnique().HasDatabaseName("EmailIndex");
        });

        modelBuilder.Entity<UserFollow>(b =>
        {
            b.HasIndex(x => new { x.UserId, x.TechnologyId }).IsUnique();
            b.HasOne(x => x.User).WithMany(u => u.Follows).HasForeignKey(x => x.UserId);
            b.HasOne(x => x.Technology).WithMany().HasForeignKey(x => x.TechnologyId);
        });

        modelBuilder.Entity<SourceReference>(b =>
        {
            b.HasIndex(x => new { x.SourceType, x.ExternalId }).IsUnique();
            b.HasIndex(x => x.VulnerabilityId);
            b.HasOne(x => x.Vulnerability)
                .WithMany(v => v.SourceReferences)
                .HasForeignKey(x => x.VulnerabilityId)
                .OnDelete(DeleteBehavior.SetNull);
            b.Property(x => x.SourceType).HasConversion<string>();
        });

        modelBuilder.Entity<SecurityIncident>(b =>
        {
            b.HasIndex(x => x.StartedAt);
            b.Property(x => x.Type).HasConversion<string>();
            b.Property(x => x.Status).HasConversion<string>();
        });

        modelBuilder.Entity<VulnerabilityEvent>(b =>
        {
            b.HasIndex(x => new { x.VulnerabilityId, x.EventType, x.EventAt }).IsUnique();
            b.HasOne(x => x.Vulnerability)
                .WithMany(v => v.Events)
                .HasForeignKey(x => x.VulnerabilityId)
                .OnDelete(DeleteBehavior.Cascade);
            b.Property(x => x.EventType).HasConversion<string>();
        });

        modelBuilder.Entity<IngestionState>(b =>
        {
            b.HasIndex(x => x.Source).IsUnique();
            b.Property(x => x.Source).HasConversion<string>();
        });
    }
}
