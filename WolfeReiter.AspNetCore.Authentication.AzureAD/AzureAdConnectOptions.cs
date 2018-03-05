using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public class AzureAdConnectOptions : OpenIdConnectOptions
    {

        public AzureAdConnectOptions()
        {
            GraphEndpoint           = "https://graph.microsoft.com/v1.0";
            GroupCacheTtlSeconds    = 60 * 60;
        }

        /// <summary>
        /// URL to invoke Graph API. Defaults to "https://graph.microsoft.com/v1.0".
        /// </summary>
        /// <returns></returns>
        public string GraphEndpoint { get; set; }

        /// <summary>
        /// Number of seconds to cache groups locally in memory before requerying Graph. Default is 3600 (1 hour).
        /// </summary>
        /// <returns></returns>
        public int GroupCacheTtlSeconds { get; set; }
    }
}