using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Threatwatch.Core.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IngestionStates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Source = table.Column<string>(type: "text", nullable: false),
                    LastSuccessfulSyncAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastAttemptedSyncAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Watermark = table.Column<string>(type: "text", nullable: true),
                    LastError = table.Column<string>(type: "text", nullable: true),
                    LastDurationMs = table.Column<long>(type: "bigint", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IngestionStates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SecurityIncidents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<string>(type: "text", nullable: false),
                    Title = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<string>(type: "text", nullable: false),
                    StartedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ResolvedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SecurityIncidents", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Technologies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Slug = table.Column<string>(type: "text", nullable: false),
                    Type = table.Column<string>(type: "text", nullable: false),
                    Ecosystem = table.Column<string>(type: "text", nullable: true),
                    Aliases = table.Column<string[]>(type: "text[]", nullable: false),
                    MatchingRules = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Technologies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserAccounts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ExternalId = table.Column<string>(type: "text", nullable: true),
                    Email = table.Column<string>(type: "text", nullable: true),
                    DisplayName = table.Column<string>(type: "text", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserAccounts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CanonicalId = table.Column<string>(type: "text", nullable: false),
                    Title = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Severity = table.Column<string>(type: "text", nullable: false),
                    CvssScore = table.Column<decimal>(type: "numeric", nullable: true),
                    CvssVector = table.Column<string>(type: "text", nullable: true),
                    CvssSource = table.Column<string>(type: "text", nullable: true),
                    PublishedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ModifiedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IsKnownExploited = table.Column<bool>(type: "boolean", nullable: false),
                    IsWithdrawn = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "UserFollows",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    UserId = table.Column<Guid>(type: "uuid", nullable: false),
                    TechnologyId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserFollows", x => x.Id);
                    table.ForeignKey(
                        name: "FK_UserFollows_Technologies_TechnologyId",
                        column: x => x.TechnologyId,
                        principalTable: "Technologies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_UserFollows_UserAccounts_UserId",
                        column: x => x.UserId,
                        principalTable: "UserAccounts",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AffectedPackages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    VulnerabilityId = table.Column<Guid>(type: "uuid", nullable: false),
                    Ecosystem = table.Column<string>(type: "text", nullable: false),
                    PackageName = table.Column<string>(type: "text", nullable: false),
                    DisplayName = table.Column<string>(type: "text", nullable: false),
                    AffectedRanges = table.Column<string>(type: "jsonb", nullable: false),
                    FixedVersions = table.Column<string[]>(type: "text[]", nullable: false),
                    PackageUrl = table.Column<string>(type: "text", nullable: true),
                    Provenance = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AffectedPackages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AffectedPackages_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SourceReferences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SourceType = table.Column<string>(type: "text", nullable: false),
                    ExternalId = table.Column<string>(type: "text", nullable: false),
                    Url = table.Column<string>(type: "text", nullable: true),
                    PublishedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SourceModifiedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    VulnerabilityId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SourceReferences", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SourceReferences_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "VulnerabilityAliases",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    VulnerabilityId = table.Column<Guid>(type: "uuid", nullable: false),
                    Alias = table.Column<string>(type: "text", nullable: false),
                    AliasType = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilityAliases", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VulnerabilityAliases_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "VulnerabilityEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    VulnerabilityId = table.Column<Guid>(type: "uuid", nullable: false),
                    EventType = table.Column<string>(type: "text", nullable: false),
                    EventAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Details = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VulnerabilityEvents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VulnerabilityEvents_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AffectedPackages_Ecosystem_PackageName",
                table: "AffectedPackages",
                columns: new[] { "Ecosystem", "PackageName" });

            migrationBuilder.CreateIndex(
                name: "IX_AffectedPackages_VulnerabilityId_Ecosystem_PackageName",
                table: "AffectedPackages",
                columns: new[] { "VulnerabilityId", "Ecosystem", "PackageName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IngestionStates_Source",
                table: "IngestionStates",
                column: "Source",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_StartedAt",
                table: "SecurityIncidents",
                column: "StartedAt");

            migrationBuilder.CreateIndex(
                name: "IX_SourceReferences_SourceType_ExternalId",
                table: "SourceReferences",
                columns: new[] { "SourceType", "ExternalId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SourceReferences_VulnerabilityId",
                table: "SourceReferences",
                column: "VulnerabilityId");

            migrationBuilder.CreateIndex(
                name: "IX_Technologies_Slug",
                table: "Technologies",
                column: "Slug",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserAccounts_ExternalId",
                table: "UserAccounts",
                column: "ExternalId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_UserFollows_TechnologyId",
                table: "UserFollows",
                column: "TechnologyId");

            migrationBuilder.CreateIndex(
                name: "IX_UserFollows_UserId_TechnologyId",
                table: "UserFollows",
                columns: new[] { "UserId", "TechnologyId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_CanonicalId",
                table: "Vulnerabilities",
                column: "CanonicalId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_IsKnownExploited",
                table: "Vulnerabilities",
                column: "IsKnownExploited");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_ModifiedAt",
                table: "Vulnerabilities",
                column: "ModifiedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_PublishedAt",
                table: "Vulnerabilities",
                column: "PublishedAt");

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_Severity",
                table: "Vulnerabilities",
                column: "Severity");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityAliases_Alias",
                table: "VulnerabilityAliases",
                column: "Alias",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityAliases_VulnerabilityId",
                table: "VulnerabilityAliases",
                column: "VulnerabilityId");

            migrationBuilder.CreateIndex(
                name: "IX_VulnerabilityEvents_VulnerabilityId_EventType_EventAt",
                table: "VulnerabilityEvents",
                columns: new[] { "VulnerabilityId", "EventType", "EventAt" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AffectedPackages");

            migrationBuilder.DropTable(
                name: "IngestionStates");

            migrationBuilder.DropTable(
                name: "SecurityIncidents");

            migrationBuilder.DropTable(
                name: "SourceReferences");

            migrationBuilder.DropTable(
                name: "UserFollows");

            migrationBuilder.DropTable(
                name: "VulnerabilityAliases");

            migrationBuilder.DropTable(
                name: "VulnerabilityEvents");

            migrationBuilder.DropTable(
                name: "Technologies");

            migrationBuilder.DropTable(
                name: "UserAccounts");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");
        }
    }
}
