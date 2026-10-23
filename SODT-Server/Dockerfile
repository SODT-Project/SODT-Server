FROM mcr.microsoft.com/dotnet/runtime:10.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 45645

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["SODT-Server.csproj", "./"]
RUN dotnet restore "SODT-Server.csproj"
COPY . .
WORKDIR "/src/"
RUN dotnet build "./SODT-Server.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./SODT-Server.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
USER root
RUN mkdir -p /app/certs/public /app/certs/private \
    && chown -R $APP_UID:$APP_UID /app/certs
USER $APP_UID
ENTRYPOINT ["dotnet", "SODT-Server.dll"]
