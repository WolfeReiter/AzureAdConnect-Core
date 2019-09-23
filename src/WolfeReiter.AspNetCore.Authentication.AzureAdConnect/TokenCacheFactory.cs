
using System;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public interface ITokenCacheFactory
    {
        TokenCache Instance { get; }
    }

    public class TokenCacheFactory : ITokenCacheFactory
    {
        private IDistributedCache DistributedCache { get; set; }
        private IDataProtectionProvider DataProtectionProvider { get; set; }
        //Token cache is cached in-memory in this instance to avoid loading data multiple times during the request
        //For this reason this factory should always be registered as Scoped
        private TokenCache TokenCache { get; set; }

        public TokenCacheFactory(IDistributedCache distributedCache, IDataProtectionProvider dataProtectionProvider)
        {
            DistributedCache       = distributedCache;
            DataProtectionProvider = dataProtectionProvider;
        }

        public TokenCache Instance
        {
            get 
            {
                if (TokenCache == null) TokenCache = new AzureAdDistributedTokenCache(DistributedCache, DataProtectionProvider);
                return TokenCache;
            }
        }
    }
}