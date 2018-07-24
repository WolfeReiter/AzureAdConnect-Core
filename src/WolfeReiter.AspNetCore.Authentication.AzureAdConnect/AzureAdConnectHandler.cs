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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    /// <summary>
    /// A per-request authentication handler for AzureAD that maps Groups to RoleClaims.
    /// </summary>
    public class AzureAdConnectHandler : OpenIdConnectHandler, IAuthenticationSignOutHandler
    {
        object _lock = new Object();
        new ILogger Logger { get; set; }
        ILoggerFactory LoggerFactory { get; set; }
        public AzureAdConnectHandler(IOptionsMonitor<OpenIdConnectOptions> options, ILoggerFactory logger, HtmlEncoder htmlEncoder, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, htmlEncoder, encoder, clock)
        {
            Logger = logger.CreateLogger<AzureAdConnectHandler>();
            LoggerFactory = logger;
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
                    if (Options is AzureAdConnectOptions) _azureAdConnectOptions = (AzureAdConnectOptions)Options;
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
            if (result.Succeeded) await AddAzureAdGroupRoleClaims(result.Principal);
            return result;  
        }

        async Task AddAzureAdGroupRoleClaims(ClaimsPrincipal incomingPrincipal)
        {
            if (incomingPrincipal != null && incomingPrincipal.Identity.IsAuthenticated == true)
            {
                Tuple<DateTime, IEnumerable<string>> grouple = null;
                IEnumerable<string> groups                   = Enumerable.Empty<string>();
                IEnumerable<string> oldGroups                = Enumerable.Empty<string>();
                var identity                                 = (ClaimsIdentity)incomingPrincipal.Identity;
                var identityKey                              = identity.Name;
                var cacheValid                               = false;

                try
                {
                    if (PrincipalRoleCache.TryGetValue(identityKey, out grouple))
                    {
                        lock(_lock) //prevent concurrent access to grouple Tuple
                        {
                            if(grouple != null)
                            {
                                var expiration = grouple.Item1.AddSeconds(AzureAdConnectOptions.GroupCacheTtlSeconds);
                                if (DateTime.UtcNow > expiration ||
                                    grouple.Item2.Count() != identity.Claims.Count(x => x.Type == "groups"))
                                {
                                    oldGroups = grouple.Item2;
                                    //don't need to check return because if it failed, then the entry was removed already
                                    //or we'll try again.
                                    //don't re-use the "grouple" variable because the out of TryRemove can be null.
                                    Tuple<DateTime, IEnumerable<string>> removedGrouple = null;
                                    PrincipalRoleCache.TryRemove(identityKey, out removedGrouple);
                                }
                                else
                                {
                                    cacheValid = true;
                                    groups = grouple.Item2;
                                }
                            }
                        }
                    }

                    if (!cacheValid)
                    {
                        var result = await AzureGraphHelper().AzureGroups(incomingPrincipal);
                        groups = result.Select(x => x.DisplayName);
                        grouple = new Tuple<DateTime, IEnumerable<string>>(DateTime.UtcNow, groups);
                        PrincipalRoleCache.AddOrUpdate(identityKey, grouple, (key, oldGrouple) => grouple);
                    }

                    foreach (var group in groups)
                    {
                        //add AzureAD Group claims as Roles.
                        identity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogWarning(ex, "Exception Mapping Groups to Roles");
                    identity.AddClaim(new Claim(ClaimTypes.AuthorizationDecision, String.Format("AzureAD-Group-Lookup-Error:{0:yyyy-MM-dd_HH:mm.ss}Z", DateTime.UtcNow)));
                    //Handle intermittent server problem by keeping old groups if they existed.
                    if (oldGroups.Any()) 
                    {
                        grouple = new Tuple<DateTime, IEnumerable<string>>(DateTime.UtcNow.AddSeconds(-(AzureAdConnectOptions.GroupCacheTtlSeconds / 2)), oldGroups);
                        PrincipalRoleCache.AddOrUpdate(identityKey, grouple, (key, oldGrouple) => grouple);
                        foreach (var group in oldGroups)
                        {
                            //add AzureAD Group claims as Roles.
                            identity.AddClaim(new Claim(ClaimTypes.Role, group, ClaimValueTypes.String, "AzureAD"));
                        }
                    }
                }
            }
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