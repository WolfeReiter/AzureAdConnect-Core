using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    /// <summary>
    /// Options to be configured and loaded as a Singleton.
    /// </summary>
    public class AzureAdConnectOptions 
    {
        public AzureAdConnectOptions()
        {
            GraphAuthority         = "https://graph.microsoft.com";
            GraphApiVersion        = "v1.0";
            GroupCacheTtlSeconds   = 60 * 60;
            RoleFilterPattern      = "";
            RemoveAzureGroupClaims = true;
        }
        /// <summary>
        /// URL to invoke Graph API. Defaults to &quot;https://graph.microsoft.com"&quot;.
        /// </summary>
        /// <returns></returns>
        public string GraphAuthority { get; set; }

        /// <summary>
        /// Microsoft Graph API version to target. Defaults to &quot;v1.0&quot;.
        /// </summary>
        /// <returns></returns>
        public string GraphApiVersion { get; set; }
        public string GraphEndpoint => string.Format("{0}/{1}", GraphAuthority, GraphApiVersion); 

        /// <summary>
        /// Number of seconds to cache groups locally in memory before requerying Graph. Default is 3600 (1 hour).
        /// </summary>
        /// <returns></returns>
        public int GroupCacheTtlSeconds { get; set; }

        /// <summary>
        /// regex pattern to filter group names. Only matching group names from Microsoft Graph will be converted to Role names in the ClaimsIdentity.
        /// </summary>
        /// <value></value>
        public string RoleFilterPattern { get; set; }

        /// <summary>
        /// When true, remove group IDs after processing them to get group names and convert those to Roles. This is to reduce cookie size. Default is true.
        /// </summary>
        /// <value></value>
        public bool RemoveAzureGroupClaims { get; set; }

        /// <summary>
        /// Same value as in OpenIdConnectOptions.
        /// </summary>
        /// <value></value>
        public string ClientId { get; set; }

        /// <summary>
        /// Same value as in OpenIdConnectOptions.
        /// </summary>
        /// <value></value>
        public string ClientSecret { get; set; }
        
        /// <summary>
        /// Same value as in OpenIdConnectOptions.
        /// </summary>
        /// <value></value>
        public string Authority { get; set; }
    }
}