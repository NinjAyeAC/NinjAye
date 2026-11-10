FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY server/NinjAye.Server/NinjAye.Server.csproj server/NinjAye.Server/
RUN dotnet restore server/NinjAye.Server/NinjAye.Server.csproj

COPY server/NinjAye.Server/ server/NinjAye.Server/
COPY database/ database/
RUN dotnet publish server/NinjAye.Server/NinjAye.Server.csproj \
    -c Release \
    -o /out \
    --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out/ ./
COPY --from=build /src/database/ ./database/

ENV ASPNETCORE_URLS=http://0.0.0.0:8080
ENV NinjAye__Storage=postgres

EXPOSE 8080
ENTRYPOINT ["dotnet", "NinjAye.Server.dll"]
