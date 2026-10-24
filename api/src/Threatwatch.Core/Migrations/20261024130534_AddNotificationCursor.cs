using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Threatwatch.Core.Migrations
{
    /// <inheritdoc />
    public partial class AddNotificationCursor : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "LastNotificationsReadAt",
                table: "Users",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "LastNotificationsReadAt",
                table: "Users");
        }
    }
}
