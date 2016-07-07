using System;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper.Tests
{
    /// <summary>
    /// This represents the entity of ADAL wrapper.
    /// </summary>
    public class AdalWrapper
    {
        private readonly IAuthenticationContextWrapper _authContext;

        /// <summary>
        /// Initialises a new instance of the <see cref="AdalWrapper"/> class.
        /// </summary>
        /// <param name="authContext"><see cref="IAuthenticationContextWrapper"/> instance.</param>
        public AdalWrapper(IAuthenticationContextWrapper authContext)
        {
            if (authContext == null)
            {
                throw new ArgumentNullException(nameof(authContext));
            }

            this._authContext = authContext;
        }

        /// <summary>
        /// Gets the acquire token.
        /// </summary>
        /// <param name="resource">Resource URL.</param>
        /// <param name="clientId">Client Id of the service principle.</param>
        /// <param name="clientSecret">Client secret of the service principle.</param>
        /// <returns>Returns the <see cref="IAuthenticationResultWrapper" /> instance.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, string clientSecret)
        {
            var credential = new ClientCredential(clientId, clientSecret);
            return await this._authContext.AcquireTokenAsync(resource, credential).ConfigureAwait(false);
        }

#if NET451
        /// <summary>
        /// Gets the acquire token.
        /// </summary>
        /// <param name="resource">Resource URL.</param>
        /// <param name="clientId">Client Id of the Azure Active Directory registered app.</param>
        /// <param name="username">Username.</param>
        /// <param name="password">Password.</param>
        /// <returns>Returns the <see cref="IAuthenticationResultWrapper" /> instance.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, string username, string password)
        {
            var credential = new UserPasswordCredential(username, password);
            return await this._authContext.AcquireTokenAsync(resource, clientId, credential).ConfigureAwait(false);
        }
#endif
    }
}