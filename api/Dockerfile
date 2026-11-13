FROM mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src
COPY Threatwatch.sln Directory.Build.props ./
COPY src/Threatwatch.Core/*.csproj src/Threatwatch.Core/
COPY src/Threatwatch.Ingestion/*.csproj src/Threatwatch.Ingestion/
COPY src/Threatwatch.Api/*.csproj src/Threatwatch.Api/
COPY tests/Threatwatch.Tests/*.csproj tests/Threatwatch.Tests/
RUN dotnet restore src/Threatwatch.Api/Threatwatch.Api.csproj
COPY src/ src/
RUN dotnet publish src/Threatwatch.Api/Threatwatch.Api.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app .
# Data Protection keys live in /app/data-protection-keys (mounted as a volume); the image's non-root user owns it.
RUN mkdir -p /app/data-protection-keys && chown -R $APP_UID /app/data-protection-keys
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:5080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_gcServer=0
EXPOSE 5080
ENTRYPOINT ["dotnet", "Threatwatch.Api.dll"]
