using System;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper
{
    /// <summary>
    /// This represents the wrapper entity for the <see cref="AuthenticationResult"/> class.
    /// </summary>
    public class AuthenticationResultWrapper : IAuthenticationResultWrapper
    {
        private bool _disposed;

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationResultWrapper"/> class.
        /// </summary>
        /// <param name="result"><see cref="AuthenticationResult"/> instance.</param>
        public AuthenticationResultWrapper(AuthenticationResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            this.Result = result;
        }

        /// <summary>
        /// Gets the <see cref="AuthenticationResult"/> instance.
        /// </summary>
        public AuthenticationResult Result { get; }

        /// <summary>
        /// Gets the type of the Access Token returned.
        /// </summary>
        public string AccessTokenType => this.Result.AccessTokenType;

        /// <summary>
        /// Gets the Access Token requested.
        /// </summary>
        public string AccessToken => this.Result.AccessToken;

        /// <summary>
        /// Gets the point in time in which the Access Token returned in the AccessToken property ceases to be valid.
        /// This value is calculated based on current UTC time measured locally and the value expiresIn received from the service.
        /// </summary>
        public DateTimeOffset ExpiresOn => this.Result.ExpiresOn;

        /// <summary>
        /// Gets an identifier for the tenant the token was acquired from. This property will be null if tenant information is not returned by the service.
        /// </summary>
        public string TenantId => this.Result.TenantId;

        /// <summary>
        /// Gets user information including user Id. Some elements in UserInfo might be null if not returned by the service.
        /// </summary>
        public UserInfo UserInfo => this.Result.UserInfo;

        /// <summary>
        /// Gets the entire Id Token if returned by the service or null if no Id Token is returned.
        /// </summary>
        public string IdToken => this.Result.IdToken;

        /// <summary>
        /// Creates authorization header from authentication result.
        /// </summary>
        /// <returns>Created authorization header</returns>
        public string CreateAuthorizationHeader()
        {
            return this.Result.CreateAuthorizationHeader();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (this._disposed)
            {
                return;
            }

            this._disposed = true;
        }
    }
}