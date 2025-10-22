using Microsoft.Graph;
using ModelContextProtocol.Server;
using System.ComponentModel;
using System.IdentityModel.Tokens.Jwt;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Core;

namespace MCPToolWeb
{
    [McpServerToolType]
    public class TodosMcpTool
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogger<TodosMcpTool> _logger;

        public TodosMcpTool(IHttpContextAccessor httpContextAccessor, ILogger<TodosMcpTool> logger)
        {
            _httpContextAccessor = httpContextAccessor;
            _logger = logger;

            _logger.LogInformation("Initial TodosMcpTool.");
        }

        [McpServerTool, Description("Lists Azure Blob Storage containers for the configured storage account using the caller's bearer token (expects token audience for Azure Storage).")]
        public async Task<List<string>> ListBlobContainersAsync(
            [Description("Optional prefix to filter container names")] string? namePrefix = null,
            [Description("Max containers to return (default 100)")] int max = 100)
        {
            var results = new List<string>();
            try
            {
                // 1. Extract bearer token
                var rawHeader = _httpContextAccessor.HttpContext?.Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrWhiteSpace(rawHeader) || !rawHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("No bearer token found in Authorization header.");
                    return results;
                }
                var accessToken = rawHeader.Substring("Bearer ".Length).Trim();
                _logger.LogDebug("Extracted bearer token of length {Length}.", accessToken.Length);

                // 2. Parse JWT to get expiry (exp) for credential
                DateTimeOffset expiresOn = DateTimeOffset.UtcNow.AddMinutes(30);
                try
                {
                    var handler = new JwtSecurityTokenHandler();
                    var jwt = handler.ReadJwtToken(accessToken);
                    var expClaim = jwt.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
                    if (long.TryParse(expClaim, out var expSeconds))
                    {
                        var epoch = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
                        // ensure not in the past
                        if (epoch > DateTimeOffset.UtcNow) expiresOn = epoch;
                    }
                }
                catch (Exception exJwt)
                {
                    _logger.LogDebug(exJwt, "Failed to parse JWT exp claim; using default expiry.");
                }

                // 3. Build a TokenCredential from static token
                var credential = new StaticBearerTokenCredential(accessToken, expiresOn);

                // 4. Resolve storage account URL (from config or header)
                var config = _httpContextAccessor.HttpContext!
                    .RequestServices
                    .GetRequiredService<IConfiguration>();

                var accountUrl = config["Storage:AccountUrl"];
                if (string.IsNullOrWhiteSpace(accountUrl))
                {
                    _logger.LogError("Storage:AccountUrl not configured.");
                    return results;
                }

                // 5. Create BlobServiceClient locally with caller's token
                var blobServiceClient = new BlobServiceClient(new Uri(accountUrl), credential);

                _logger.LogInformation("Listing blob containers prefix={Prefix} max={Max}", namePrefix, max);

                await foreach (BlobContainerItem item in blobServiceClient.GetBlobContainersAsync())
                {
                    if (results.Count >= max) break;
                    if (namePrefix != null && !item.Name.StartsWith(namePrefix, StringComparison.OrdinalIgnoreCase))
                        continue;
                    results.Add(item.Name);
                }

                _logger.LogInformation("Listed {Count} containers.", results.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list blob containers.");
                throw;
            }
            return results;
        }

        // Local static credential that always returns the received bearer token until its exp
        private sealed class StaticBearerTokenCredential : TokenCredential
        {
            private readonly string _token;
            private readonly DateTimeOffset _expiresOn;
            public StaticBearerTokenCredential(string token, DateTimeOffset expiresOn)
            {
                _token = token;
                _expiresOn = expiresOn;
            }
            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
                => new AccessToken(_token, _expiresOn);

            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
                => new ValueTask<AccessToken>(new AccessToken(_token, _expiresOn));
        }
    }
}
