using System;
using System.Threading.Tasks;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper
{
    /// <summary>
    /// This represents the wrapper entity for the <see cref="AuthenticationContext"/> class.
    /// </summary>
    public class AuthenticationContextWrapper : IAuthenticationContextWrapper
    {
        private bool _disposed;

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextWrapper"/> class.
        /// </summary>
        /// <param name="context"><see cref="AuthenticationContext"/> instance.</param>
        public AuthenticationContextWrapper(AuthenticationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            this.Context = context;
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextWrapper"/> class.
        /// </summary>
        /// <param name="authority">Authority URL.</param>
        public AuthenticationContextWrapper(string authority)
        {
            if (string.IsNullOrWhiteSpace(authority))
            {
                throw new ArgumentNullException(nameof(authority));
            }

            this.Context = new AuthenticationContext(authority);
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextWrapper"/> class.
        /// </summary>
        /// <param name="authority">Authority URL.</param>
        /// <param name="tokenCache"><see cref="TokenCache"/> instance.</param>
        public AuthenticationContextWrapper(string authority, TokenCache tokenCache)
        {
            if (string.IsNullOrWhiteSpace(authority))
            {
                throw new ArgumentNullException(nameof(authority));
            }

            if (tokenCache == null)
            {
                throw new ArgumentNullException(nameof(tokenCache));
            }

            this.Context = new AuthenticationContext(authority, tokenCache);
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextWrapper"/> class.
        /// </summary>
        /// <param name="authority">Authority URL.</param>
        /// <param name="validateAuthority">Value indicating whether to validate authority or not.</param>
        public AuthenticationContextWrapper(string authority, bool validateAuthority)
        {
            if (string.IsNullOrWhiteSpace(authority))
            {
                throw new ArgumentNullException(nameof(authority));
            }

            this.Context = new AuthenticationContext(authority, validateAuthority);
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextWrapper"/> class.
        /// </summary>
        /// <param name="authority">Authority URL.</param>
        /// <param name="validateAuthority">Value indicating whether to validate authority or not.</param>
        /// <param name="tokenCache"><see cref="TokenCache"/> instance.</param>
        public AuthenticationContextWrapper(string authority, bool validateAuthority, TokenCache tokenCache)
        {
            if (string.IsNullOrWhiteSpace(authority))
            {
                throw new ArgumentNullException(nameof(authority));
            }

            if (tokenCache == null)
            {
                throw new ArgumentNullException(nameof(tokenCache));
            }

            this.Context = new AuthenticationContext(authority, validateAuthority, tokenCache);
        }

        /// <summary>
        /// Gets the <see cref="AuthenticationContext"/> instance.
        /// </summary>
        public AuthenticationContext Context { get; }

        /// <summary>
        /// Gets address of the authority to issue token.
        /// </summary>
        public string Authority => this.Context.Authority;

        /// <summary>
        /// Gets a value indicating whether address validation is ON or OFF.
        /// </summary>
        public bool ValidateAuthority => this.Context.ValidateAuthority;

        /// <summary>
        /// Property to provide ADAL's token cache. Depending on the platform, TokenCache may have a default persistent cache or not.
        /// Library will automatically save tokens in default TokenCache whenever you obtain them. Cached tokens will be available only to the application that saved them.
        /// If the cache is persistent, the tokens stored in it will outlive the application's execution, and will be available in subsequent runs.
        /// To turn OFF token caching, set TokenCache to null.
        /// </summary>
        public TokenCache TokenCache => this.Context.TokenCache;

        /// <summary>
        /// Gets or sets correlation Id which would be sent to the service with the next request.
        /// Correlation Id is to be used for diagnostics purposes.
        /// </summary>
        public Guid CorrelationId
        {
            get
            {
                return this.Context.CorrelationId;
            }
            set
            {
                this.Context.CorrelationId = value;
            }
        }

        /// <summary>
        /// Acquires device code from the authority.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IDeviceCodeResultWrapper> AcquireDeviceCodeAsync(string resource, string clientId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            var result = await this.Context.AcquireDeviceCodeAsync(resource, clientId).ConfigureAwait(false);
            return new DeviceCodeResultWrapper(result);
        }

        /// <summary>
        /// Acquires device code from the authority.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authentication request to the authority. The parameter can be null.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IDeviceCodeResultWrapper> AcquireDeviceCodeAsync(string resource, string clientId, string extraQueryParameters)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (string.IsNullOrWhiteSpace(extraQueryParameters))
            {
                throw new ArgumentNullException(nameof(extraQueryParameters));
            }

            var result = await this.Context.AcquireDeviceCodeAsync(resource, clientId, extraQueryParameters).ConfigureAwait(false);
            return new DeviceCodeResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an device code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="deviceCodeResult">The device code result received from calling AcquireDeviceCodeAsync.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByDeviceCodeAsync(IDeviceCodeResultWrapper deviceCodeResult)
        {
            if (deviceCodeResult == null)
            {
                throw new ArgumentNullException(nameof(deviceCodeResult));
            }

            var result = await this.Context.AcquireTokenByDeviceCodeAsync(deviceCodeResult.Result).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <remarks>This feature is supported only for Azure Active Directory and Active Directory Federation Services (ADFS) on Windows 10.</remarks>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userCredential">The user credential to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, UserCredential userCredential)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (userCredential == null)
            {
                throw new ArgumentNullException(nameof(userCredential));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientId, userCredential).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userAssertion">The assertion to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, UserAssertion userAssertion)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (userAssertion == null)
            {
                throw new ArgumentNullException(nameof(userAssertion));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientId, userAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientCredential clientCredential)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCredential == null)
            {
                throw new ArgumentNullException(nameof(clientCredential));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientCredential).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, IClientAssertionCertificate clientCertificate)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCertificate == null)
            {
                throw new ArgumentNullException(nameof(clientCertificate));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientCertificate).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time. Refresh Token property will be null for this overload.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientAssertion clientAssertion)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientAssertion == null)
            {
                throw new ArgumentNullException(nameof(clientAssertion));
            }

            var result =  await this.Context.AcquireTokenAsync(resource, clientAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientCredential == null)
            {
                throw new ArgumentNullException(nameof(clientCredential));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCredential).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token. It can be null if provided earlier to acquire authorizationCode.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential, string resource)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientCredential == null)
            {
                throw new ArgumentNullException(nameof(clientCredential));
            }

            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCredential, resource).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientAssertion == null)
            {
                throw new ArgumentNullException(nameof(clientAssertion));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token. It can be null if provided earlier to acquire authorizationCode.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion, string resource)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientAssertion == null)
            {
                throw new ArgumentNullException(nameof(clientAssertion));
            }

            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientAssertion, resource).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, IClientAssertionCertificate clientCertificate)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientCertificate == null)
            {
                throw new ArgumentNullException(nameof(clientCertificate));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCertificate).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="M:Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext.AcquireTokenSilentAsync(System.String,System.String,Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier)" />.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token. It can be null if provided earlier to acquire authorizationCode.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, IClientAssertionCertificate clientCertificate, string resource)
        {
            if (string.IsNullOrWhiteSpace(authorizationCode))
            {
                throw new ArgumentNullException(nameof(authorizationCode));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (clientCertificate == null)
            {
                throw new ArgumentNullException(nameof(clientCertificate));
            }

            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            var result = await this.Context.AcquireTokenByAuthorizationCodeAsync(authorizationCode, redirectUri, clientCertificate, resource).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientCredential clientCredential, UserAssertion userAssertion)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCredential == null)
            {
                throw new ArgumentNullException(nameof(clientCredential));
            }

            if (userAssertion == null)
            {
                throw new ArgumentNullException(nameof(userAssertion));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientCredential, userAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, IClientAssertionCertificate clientCertificate, UserAssertion userAssertion)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCertificate == null)
            {
                throw new ArgumentNullException(nameof(clientCertificate));
            }

            if (userAssertion == null)
            {
                throw new ArgumentNullException(nameof(userAssertion));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientCertificate, userAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, ClientAssertion clientAssertion, UserAssertion userAssertion)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientAssertion == null)
            {
                throw new ArgumentNullException(nameof(clientAssertion));
            }

            if (userAssertion == null)
            {
                throw new ArgumentNullException(nameof(userAssertion));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientAssertion, userAssertion).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientId, userId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <param name="parameters">Instance of PlatformParameters containing platform specific arguments and information.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, string clientId, UserIdentifier userId, IPlatformParameters parameters)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientId, userId, parameters).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, ClientCredential clientCredential, UserIdentifier userId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCredential == null)
            {
                throw new ArgumentNullException(nameof(clientCredential));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientCredential, userId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, IClientAssertionCertificate clientCertificate, UserIdentifier userId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientCertificate == null)
            {
                throw new ArgumentNullException(nameof(clientCertificate));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientCertificate, userId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenSilentAsync(string resource, ClientAssertion clientAssertion, UserIdentifier userId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (clientAssertion == null)
            {
                throw new ArgumentNullException(nameof(clientAssertion));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var result = await this.Context.AcquireTokenSilentAsync(resource, clientAssertion, userId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>
        /// Gets URL of the authorize endpoint including the query parameters.
        /// </summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authentication request to the authority. The parameter can be null.</param>
        /// <returns>URL of the authorize endpoint including the query parameters.</returns>
        public async Task<Uri> GetAuthorizationRequestUrlAsync(string resource, string clientId, Uri redirectUri, UserIdentifier userId, string extraQueryParameters)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrWhiteSpace(extraQueryParameters))
            {
                throw new ArgumentNullException(nameof(extraQueryParameters));
            }

            return await this.Context.GetAuthorizationRequestUrlAsync(resource, clientId, redirectUri, userId, extraQueryParameters).ConfigureAwait(false);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="parameters">An object of type PlatformParameters which may pass additional parameters used for authorization.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientId, redirectUri, parameters).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="parameters">An object of type PlatformParameters which may pass additional parameters used for authorization.</param>
        /// <param name="userId">Identifier of the user token is requested for. If created from DisplayableId, this parameter will be used to pre-populate the username field in the authentication form. Please note that the end user can still edit the username field and authenticate as a different user.
        /// If you want to be notified of such change with an exception, create UserIdentifier with type RequiredDisplayableId. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientId, redirectUri, parameters, userId).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
        }

        /// <summary>Acquires security token from the authority.</summary>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token.</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. If created from DisplayableId, this parameter will be used to pre-populate the username field in the authentication form. Please note that the end user can still edit the username field and authenticate as a different user.
        /// If you want to be notified of such change with an exception, create UserIdentifier with type RequiredDisplayableId. This parameter can be <see cref="T:Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" />.Any.</param>
        /// <param name="parameters">Parameters needed for interactive flow requesting authorization code. Pass an instance of PlatformParameters.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authentication request to the authority. The parameter can be null.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<IAuthenticationResultWrapper> AcquireTokenAsync(string resource, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId, string extraQueryParameters)
        {
            if (string.IsNullOrWhiteSpace(resource))
            {
                throw new ArgumentNullException(nameof(resource));
            }

            if (string.IsNullOrWhiteSpace(clientId))
            {
                throw new ArgumentNullException(nameof(clientId));
            }

            if (redirectUri == null)
            {
                throw new ArgumentNullException(nameof(redirectUri));
            }

            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrWhiteSpace(extraQueryParameters))
            {
                throw new ArgumentNullException(nameof(extraQueryParameters));
            }

            var result = await this.Context.AcquireTokenAsync(resource, clientId, redirectUri, parameters, userId, extraQueryParameters).ConfigureAwait(false);
            return new AuthenticationResultWrapper(result);
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