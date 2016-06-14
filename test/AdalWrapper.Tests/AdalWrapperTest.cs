using Aliencube.AdalWrapper.Tests.Fixtures;

using FluentAssertions;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

using Moq;

using Xunit;

namespace Aliencube.AdalWrapper.Tests
{
    /// <summary>
    /// This represents the test entity for the <see cref="AdalWrapper"/> class.
    /// </summary>
    public class AdalWrapperTest : IClassFixture<AdalWrapperFixture>
    {
        private readonly Mock<IAuthenticationResultWrapper> _authResult;
        private readonly Mock<IAuthenticationContextWrapper> _authContext;
        private readonly AdalWrapper _wrapper;

        /// <summary>
        /// Initialises a new instance of the <see cref="AdalWrapperTest"/> class.
        /// </summary>
        /// <param name="fixture"><see cref="AdalWrapperFixture"/> instance.</param>
        public AdalWrapperTest(AdalWrapperFixture fixture)
        {
            this._authResult = fixture.AuthenticationResult;
            this._authContext = fixture.AuthenticationContext;
            this._wrapper = fixture.AdalWrapper;
        }

        /// <summary>
        /// Tests whether the method should return result or not.
        /// </summary>
        /// <param name="resource">Resource URL value.</param>
        /// <param name="clientId">Client Id value.</param>
        /// <param name="clientSecret">Client secret value.</param>
        /// <param name="accessToken">Access token value.</param>
        [Theory]
        [InlineData("resource", "clientId", "clientSecret", "ACCESS_TOKEN")]
        public async void Given_Parameters_Method_ShouldReturn_Result(string resource, string clientId, string clientSecret, string accessToken)
        {
            this._authResult.SetupGet(p => p.AccessToken).Returns(accessToken);
            this._authContext.Setup(p => p.AcquireTokenAsync(It.IsAny<string>(), It.IsAny<ClientCredential>())).ReturnsAsync(this._authResult.Object);

            var result = await this._wrapper.AcquireTokenAsync(resource, clientId, clientSecret).ConfigureAwait(false);
            result.AccessToken.Should().BeEquivalentTo(accessToken);
        }

        /// <summary>
        /// Tests whether the method should return result or not.
        /// </summary>
        /// <param name="resource">Resource URL value.</param>
        /// <param name="clientId">Client Id value.</param>
        /// <param name="username">Username value.</param>
        /// <param name="password">Password value.</param>
        /// <param name="accessToken">Access token value.</param>
        [Theory]
        [InlineData("resource", "clientId", "username", "password", "ACCESS_TOKEN")]
        public async void Given_Parameters_Method_ShouldReturn_Result(string resource, string clientId, string username, string password, string accessToken)
        {
            this._authResult.SetupGet(p => p.AccessToken).Returns(accessToken);
            this._authContext.Setup(p => p.AcquireTokenAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<UserCredential>())).ReturnsAsync(this._authResult.Object);

            var result = await this._wrapper.AcquireTokenAsync(resource, clientId, username, password).ConfigureAwait(false);
            result.AccessToken.Should().BeEquivalentTo(accessToken);
        }
    }
}