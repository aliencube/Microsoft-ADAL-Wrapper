using System;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper
{
    /// <summary>
    /// This provides interfaces to the <see cref="AuthenticationResultWrapper"/> class.
    /// </summary>
    public interface IAuthenticationResultWrapper : IDisposable
    {
        /// <summary>
        /// Gets the <see cref="AuthenticationResult"/> instance.
        /// </summary>
        AuthenticationResult Result { get; }

        /// <summary>
        /// Gets the type of the Access Token returned.
        /// </summary>
        string AccessTokenType { get; }

        /// <summary>
        /// Gets the Access Token requested.
        /// </summary>
        string AccessToken { get; }

        /// <summary>
        /// Gets the point in time in which the Access Token returned in the AccessToken property ceases to be valid.
        /// This value is calculated based on current UTC time measured locally and the value expiresIn received from the service.
        /// </summary>
        DateTimeOffset ExpiresOn { get; }

        /// <summary>
        /// Gets an identifier for the tenant the token was acquired from. This property will be null if tenant information is not returned by the service.
        /// </summary>
        string TenantId { get; }

        /// <summary>
        /// Gets user information including user Id. Some elements in UserInfo might be null if not returned by the service.
        /// </summary>
        UserInfo UserInfo { get; }

        /// <summary>
        /// Gets the entire Id Token if returned by the service or null if no Id Token is returned.
        /// </summary>
        string IdToken { get; }

        /// <summary>
        /// Creates authorization header from authentication result.
        /// </summary>
        /// <returns>Created authorization header</returns>
        string CreateAuthorizationHeader();
    }
}