using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Principal;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Text.RegularExpressions;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    /// <summary>
    /// A per-request authentication handler for AzureAD that maps Groups to RoleClaims.
    /// </summary>
    public class AzureAdConnectHandler : OpenIdConnectHandler, IAuthenticationSignOutHandler
    {
        new ILogger Logger { get; set; }
        ILoggerFactory LoggerFactory { get; set; }

        readonly string RoleFilterPattern;
        readonly bool RemoveAzureGroupClaims;
        public AzureAdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, HtmlEncoder htmlEncoder, UrlEncoder encoder, ISystemClock clock, IConfiguration configuration)
            : base(options, logger, htmlEncoder, encoder, clock)
        {
            Logger = logger.CreateLogger<AzureAdConnectHandler>();
            LoggerFactory = logger;
            RoleFilterPattern = configuration.GetValue<string>("AzureAD:groupNameFilterPattern", "");
            RemoveAzureGroupClaims = configuration.GetValue<bool>("AzureAD:removeGroupClaims", true);
        }

        protected AzureGraphHelper AzureGraphHelper()
        {
            return new AzureGraphHelper(AzureAdConnectOptions, this.LoggerFactory);
        }

        AzureAdConnectOptions _azureAdConnectOptions = null;
        protected AzureAdConnectOptions AzureAdConnectOptions 
        {
             get 
             {
                 if(_azureAdConnectOptions is null) 
                 {
                    if (Options is AzureAdConnectOptions options) _azureAdConnectOptions = options;
                    else _azureAdConnectOptions = new AzureAdConnectOptions(Options);
                 }
                 return _azureAdConnectOptions;
             }
             set { _azureAdConnectOptions = value; }
        }

        /// <summary>
        /// Invoked to process incoming OpenIdConnect messages.
        /// </summary>
        /// <returns>An <see cref="HandleRequestResult"/>.</returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var result = await base.HandleRemoteAuthenticateAsync();
            if (result.Succeeded) 
            {
                ClaimsIdentity claimsIdentity = result.Principal.Identity as ClaimsIdentity;
                Regex roleFilter = null;
                if (!String.IsNullOrWhiteSpace(RoleFilterPattern)) roleFilter = new Regex(RoleFilterPattern);

                //convert Azure "groups" claim of Guids to Role claims by looking up the Group DisplayName in Microsoft Graph
                var groups = (await AzureGraphHelper().AzureGroups(result.Principal)).Select(x => x.DisplayName);
                foreach (var group in groups)
                {
                    //the filter regex will only add matched role names that are used by the application in order to limit the cookie size
                    if (roleFilter == null || roleFilter.IsMatch(group))
                    {
                        claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                    }
                }

                //remove groups claims -- which are simply GUIDs -- in order to reduce cookie size
                if (RemoveAzureGroupClaims)
                {
                    //remove Azure "groups" claims to save space
                    var groupClaims = claimsIdentity.Claims.Where(x => x.Type == "groups").ToList();
                    foreach (var claim in groupClaims)
                    {
                        claimsIdentity.TryRemoveClaim(claim);
                    }
                }
            }
            return result;  
        }

         protected override async Task<bool> HandleRemoteSignOutAsync()
         {
             return await base.HandleRemoteSignOutAsync();
         }

        static ConcurrentDictionary<string, Tuple<DateTime, IEnumerable<string>>> PrincipalRoleCache { get; set; }
        static AzureAdConnectHandler()
        {
            PrincipalRoleCache = new ConcurrentDictionary<string, Tuple<DateTime, IEnumerable<string>>>();
        }
    }
}