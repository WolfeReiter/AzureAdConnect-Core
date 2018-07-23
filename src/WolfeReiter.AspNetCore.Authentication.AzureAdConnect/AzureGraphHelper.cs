using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Collections.Generic;
using Microsoft.Graph;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Extensions.Logging;

namespace WolfeReiter.AspNetCore.Authentication.AzureAD
{
    public class AzureGraphHelper
    {
        public AzureGraphHelper(AzureAdConnectOptions options, ILoggerFactory logger)
        {
            Options = options;
            Logger = logger.CreateLogger<AzureGraphHelper> ();
        }

        ILogger Logger { get; set; }
        AzureAdConnectOptions Options { get; set; }

        public async Task<IEnumerable<Group>> AzureGroups(ClaimsPrincipal principal)
        {
            var userObjectID = principal.FindFirst(AzureClaimTypes.ObjectIdentifier).Value;
            var ids = GroupIDs(principal);
            var graphClient = GetAuthenticatedClient();

            var tasks = new List<Task<Task<Group>>>();
            foreach(var id in ids)
            {
                //If a Group is deleted from Azure but that group is attached to a User,
                //an exception will by thrown that the requested resource does not exist.
                //If an exception is thrown by any task in Task.WhenAll() the results of all of the 
                //tasks are discarded.
                //However, attaching a Continuation to a Task changes the behavior so that the exception
                //can be interrogated later using the .IsFaulted property.
                var task = graphClient.Groups[id].Request().GetAsync()
                    .ContinueWith(t => t, TaskContinuationOptions.ExecuteSynchronously);
                tasks.Add(task);
            }
            var complete = await Task.WhenAll(tasks);

            foreach(var task in complete.Where(x => x.IsFaulted))
            {
                Logger.LogWarning(task.Exception, "Fault querying for AzureAD Group");
            }

            return complete.Where(x => x.Status == TaskStatus.RanToCompletion).Select(x => x.Result);
        }

        public GraphServiceClient GetAuthenticatedClient()
        {
            var authenticationProvider = new DelegateAuthenticationProvider(
                async(requestMessage) => 
                {
                    var token = await GraphToken();
                    requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", token);
                });
            var graphClient = new GraphServiceClient(Options.GraphEndpoint, authenticationProvider);
            return graphClient;
        }
        async Task<string> GraphToken()
        {
            var credential = new ClientCredential(Options.ClientId, Options.ClientSecret);
            var authContext = new AuthenticationContext(Options.Authority);
            AuthenticationResult result = await authContext.AcquireTokenAsync(Options.GraphAuthority, credential);
            return result.AccessToken;
        }
        static IEnumerable<string> GroupIDs(ClaimsPrincipal principal)
        {
            return principal.Claims.Where(x => x.Type == "groups").Select(x => x.Value.ToLower());
        }
    }
}