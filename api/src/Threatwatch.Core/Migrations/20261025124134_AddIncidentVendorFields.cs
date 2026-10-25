using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Threatwatch.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddIncidentVendorFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Ecosystem",
                table: "SecurityIncidents",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalId",
                table: "SecurityIncidents",
                type: "character varying(200)",
                maxLength: 200,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "SourceType",
                table: "SecurityIncidents",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Url",
                table: "SecurityIncidents",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VendorName",
                table: "SecurityIncidents",
                type: "character varying(120)",
                maxLength: 120,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "VendorSlug",
                table: "SecurityIncidents",
                type: "character varying(80)",
                maxLength: 80,
                nullable: false,
                defaultValue: "");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_SourceType_ExternalId",
                table: "SecurityIncidents",
                columns: new[] { "SourceType", "ExternalId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_Status",
                table: "SecurityIncidents",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_SecurityIncidents_VendorSlug",
                table: "SecurityIncidents",
                column: "VendorSlug");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SecurityIncidents_SourceType_ExternalId",
                table: "SecurityIncidents");

            migrationBuilder.DropIndex(
                name: "IX_SecurityIncidents_Status",
                table: "SecurityIncidents");

            migrationBuilder.DropIndex(
                name: "IX_SecurityIncidents_VendorSlug",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "Ecosystem",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "ExternalId",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "SourceType",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "Url",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "VendorName",
                table: "SecurityIncidents");

            migrationBuilder.DropColumn(
                name: "VendorSlug",
                table: "SecurityIncidents");
        }
    }
}
