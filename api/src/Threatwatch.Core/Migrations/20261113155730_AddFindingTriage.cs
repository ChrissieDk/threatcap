using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Threatwatch.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddFindingTriage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "FindingTriages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    VulnerabilityId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<string>(type: "text", nullable: false),
                    SnoozedUntil = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_FindingTriages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_FindingTriages_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_FindingTriages_Vulnerabilities_VulnerabilityId",
                        column: x => x.VulnerabilityId,
                        principalTable: "Vulnerabilities",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_FindingTriages_ProjectId_VulnerabilityId",
                table: "FindingTriages",
                columns: new[] { "ProjectId", "VulnerabilityId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_FindingTriages_VulnerabilityId",
                table: "FindingTriages",
                column: "VulnerabilityId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "FindingTriages");
        }
    }
}
