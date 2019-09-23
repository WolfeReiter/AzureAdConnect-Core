
using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public class AzureAdDistributedTokenCache : TokenCache
    {
        private IDistributedCache DistributedCache { get; set; }
        private IDataProtector DataProtector { get; set; }

        /// <summary>
        /// Constructs a token cache
        /// </summary>
        /// <param name="distributedCache">Distributed cache used for storing tokens</param>
        /// <param name="dataProtectionProvider">The protector provider for encrypting/decrypting the cached data</param>
        public AzureAdDistributedTokenCache(IDistributedCache distributedCache, IDataProtectionProvider dataProtectionProvider)
        {
            DistributedCache = distributedCache;
            DataProtector    = dataProtectionProvider.CreateProtector("AadTokens");
            BeforeAccess     = BeforeAccessNotification;
            AfterAccess      = AfterAccessNotification;
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            byte[] cachedData = DistributedCache.Get(CacheKey(args.UniqueId));

            if (cachedData != null)
            {
                //Decrypt and deserialize the cached data
                DeserializeAdalV3(DataProtector.Unprotect(cachedData));
            }
            else
            {
                //Ensures the cache is cleared in TokenCache
                DeserializeAdalV3(null);
            }
        }

        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (HasStateChanged)
            {
                var data = DataProtector.Protect(SerializeAdalV3());
                DistributedCache.Set(CacheKey(args.UniqueId), data);
                HasStateChanged = false;
            }
        }
        private string CacheKey(string uniqueId) => $"{uniqueId}_TokenCache";
    }
}