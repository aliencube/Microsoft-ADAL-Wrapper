using System;

using Moq;

namespace Aliencube.AdalWrapper.Tests.Fixtures
{
    /// <summary>
    /// This represents the fixture entity for the <see cref="AdalWrapperTest"/> class.
    /// </summary>
    public class AdalWrapperFixture : IDisposable
    {
        private bool _disposed;

        /// <summary>
        /// Initialises a new instance of the <see cref="AdalWrapperFixture"/> class.
        /// </summary>
        public AdalWrapperFixture()
        {
            this.AuthenticationResult = new Mock<IAuthenticationResultWrapper>();

            this.AuthenticationContext = new Mock<IAuthenticationContextWrapper>();

            this.AdalWrapper = new AdalWrapper(this.AuthenticationContext.Object);
        }

        /// <summary>
        /// Gets the <see cref="Mock{IAuthenticationResultWrapper}"/> instance.
        /// </summary>
        public Mock<IAuthenticationResultWrapper> AuthenticationResult { get; }

        /// <summary>
        /// Gets the <see cref="Mock{IAuthenticationContextWrapper}"/> instance.
        /// </summary>
        public Mock<IAuthenticationContextWrapper> AuthenticationContext { get; }

        /// <summary>
        /// Gets the <see cref="Tests.AdalWrapper"/> instance.
        /// </summary>
        public AdalWrapper AdalWrapper { get; }

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