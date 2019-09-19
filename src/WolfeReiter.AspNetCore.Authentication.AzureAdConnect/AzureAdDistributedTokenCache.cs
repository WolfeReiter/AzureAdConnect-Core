
using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public class AzureAdDistributedTokenCache : TokenCache
    {
        private readonly IDistributedCache _distributedCache;
        private readonly IDataProtector _dataProtector;
        private readonly string _userId;

        /// <summary>
        /// Constructs a token cache
        /// </summary>
        /// <param name="distributedCache">Distributed cache used for storing tokens</param>
        /// <param name="dataProtectionProvider">The protector provider for encrypting/decrypting the cached data</param>
        /// <param name="userId">The user's unique identifier</param>
        public AzureAdDistributedTokenCache(IDistributedCache distributedCache, IDataProtectionProvider dataProtectionProvider, string userId)
        {
            _distributedCache = distributedCache;
            _dataProtector    = dataProtectionProvider.CreateProtector("AadTokens");
            _userId           = userId;
            BeforeAccess      = BeforeAccessNotification;
            AfterAccess       = AfterAccessNotification;
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            byte[] cachedData = _distributedCache.Get(GetCacheKey());

            if (cachedData != null)
            {
                //Decrypt and deserialize the cached data
                DeserializeAdalV3(_dataProtector.Unprotect(cachedData));
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
                var data = _dataProtector.Protect(SerializeAdalV3());

                _distributedCache.Set(GetCacheKey(), data, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1)
                });

                HasStateChanged = false;
            }
        }

        private string GetCacheKey() => $"{_userId}_TokenCache";
    }
}