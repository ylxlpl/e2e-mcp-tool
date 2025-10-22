using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Logging.ApplicationInsights;
using Microsoft.Graph;
using Microsoft.Identity.Web;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.AddFilter("Microsoft.IdentityModel", LogLevel.Debug);
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApi(
        jwtOptions =>
        {
            builder.Configuration.Bind("AzureAd", jwtOptions);

            var tenantId       = builder.Configuration["AzureAd:TenantId"];

            // IMPORTANT: your token issuer is v1 (sts.windows.net/…). Add both v1 & v2 issuers.
            jwtOptions.TokenValidationParameters.ValidIssuers = new[]
            {
                $"https://sts.windows.net/{tenantId}/",
                $"https://login.microsoftonline.com/{tenantId}/v2.0"
            };

            jwtOptions.Events = new JwtBearerEvents
            {
                OnMessageReceived = ctx =>
                {
                    var log = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Auth");
                    var raw = ctx.Request.Headers.Authorization.ToString();
                    if (raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        var tok = raw.Substring(7);
                        log.LogDebug("Bearer token (first 60 chars): {Part}...", tok.Length > 60 ? tok[..60] : tok);
                    }
                    return Task.CompletedTask;
                },
                OnTokenValidated = ctx =>
                {
                    var log = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Auth");
                    var jwt = ctx.SecurityToken as JwtSecurityToken;
                    var aud = jwt?.Audiences?.FirstOrDefault() ?? ctx.Principal?.FindFirst("aud")?.Value;
                    var oid = ctx.Principal?.FindFirst("oid")?.Value;
                    var appId = ctx.Principal?.FindFirst("azp")?.Value ?? ctx.Principal?.FindFirst("appid")?.Value;
                    log.LogInformation("Token validated aud={Aud} oid={Oid} appId={AppId} issuer={Iss}", aud, oid, appId, jwt?.Issuer);
                    return Task.CompletedTask;
                },
                OnChallenge = ctx =>
                {
                    var log = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Auth");
                    log.LogWarning("Challenge issued. Error={Err} Desc={Desc}", ctx.Error, ctx.ErrorDescription);
                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = ctx =>
                {
                    var log = ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Auth");
                    log.LogError(ctx.Exception, "Authentication failed.");
                    return Task.CompletedTask;
                }
            };
        },
        identityOptions => builder.Configuration.Bind("AzureAd", identityOptions));

builder.Services.AddAuthorization();
builder.Services.AddHttpContextAccessor();

// Graph (app-only). Requires application permissions with admin consent.
var graphCredential = new DefaultAzureCredential();
builder.Services.AddSingleton(new GraphServiceClient(graphCredential, new[] { "https://graph.microsoft.com/.default" }));

var aiConn = builder.Configuration["ApplicationInsights:ConnectionString"];
builder.Logging.AddApplicationInsights(
    configureTelemetryConfiguration: cfg => cfg.ConnectionString = aiConn,
    configureApplicationInsightsLoggerOptions: _ => { });

builder.Logging.AddFilter<ApplicationInsightsLoggerProvider>(typeof(Program).FullName, LogLevel.Trace);

builder.Services.AddMcpServer()
    .WithHttpTransport()
    .WithToolsFromAssembly();

builder.Services.AddCors(o =>
{
    o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
});

var app = builder.Build();

var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("App started.");

app.UseCors();
//app.UseAuthentication();
//app.UseAuthorization();

app.MapMcp("/api/mcp");

app.Run();
