using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Threatwatch.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddProductAndEpssFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<double>(
                name: "EpssPercentile",
                table: "Vulnerabilities",
                type: "double precision",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "EpssScore",
                table: "Vulnerabilities",
                type: "double precision",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PrimaryProduct",
                table: "Vulnerabilities",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "PrimaryVendor",
                table: "Vulnerabilities",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "PriorityScore",
                table: "Vulnerabilities",
                type: "double precision",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProductType",
                table: "Vulnerabilities",
                type: "text",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EpssPercentile",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "EpssScore",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "PrimaryProduct",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "PrimaryVendor",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "PriorityScore",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "ProductType",
                table: "Vulnerabilities");
        }
    }
}
