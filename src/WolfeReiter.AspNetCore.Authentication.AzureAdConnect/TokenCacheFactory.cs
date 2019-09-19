
using System;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public interface ITokenCacheFactory
    {
        TokenCache CreateForUser(ClaimsPrincipal user);
        TokenCache Create();
    }

    public class TokenCacheFactory : ITokenCacheFactory
    {
        private readonly IDistributedCache _distributedCache;
        private readonly IDataProtectionProvider _dataProtectionProvider;
        //Token cache is cached in-memory in this instance to avoid loading data multiple times during the request
        //For this reason this factory should always be registered as Scoped
        private TokenCache TokenCache { get; set; }
        private string UserId { get; set; }

        public TokenCacheFactory(IDistributedCache distributedCache, IDataProtectionProvider dataProtectionProvider)
        {
            _distributedCache = distributedCache;
            _dataProtectionProvider = dataProtectionProvider;
        }

        public TokenCache CreateForUser(ClaimsPrincipal user)
        {
            string userId = user.ObjectIdentifier();

            if (TokenCache != null)
            {
                if (userId != UserId) throw new Exception("The cached token cache is for a different user! Make sure the token cache factory is registered as Scoped!");
                return TokenCache;
            }
            else
            {
                TokenCache = new AzureAdDistributedTokenCache( _distributedCache, _dataProtectionProvider, userId);
                UserId     = userId;
            }
            return TokenCache;
        }

        public TokenCache Create()
        {
            return CreateForUser(null);
        }
    }
}