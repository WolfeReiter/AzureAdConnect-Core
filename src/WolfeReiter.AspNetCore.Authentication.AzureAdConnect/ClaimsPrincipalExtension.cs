using System;
using System.Security.Claims;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public static class ClaimsPrincipalExtension
    {
        public static string ObjectIdentifier(this ClaimsPrincipal principal)
        {
            if(principal == null) return null;
            return principal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
        }
    }
}