using System;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper
{
    /// <summary>
    /// This represents the wrapper entity for the <see cref="DeviceCodeResult"/> class.
    /// </summary>
    public class DeviceCodeResultWrapper : IDeviceCodeResultWrapper
    {
        private bool _disposed;

        /// <summary>
        /// Initialises a new instance of the <see cref="DeviceCodeResultWrapper"/> class.
        /// </summary>
        /// <param name="result"><see cref="DeviceCodeResult"/> instance.</param>
        public DeviceCodeResultWrapper(DeviceCodeResult result)
        {
            if (result == null)
            {
                throw new ArgumentNullException(nameof(result));
            }

            this.Result = result;
        }

        /// <summary>
        /// Gets the <see cref="DeviceCodeResult"/> instance.
        /// </summary>
        public DeviceCodeResult Result { get; }

        /// <summary>
        /// User code returned by the service
        /// </summary>
        public string UserCode => this.Result.UserCode;

        /// <summary>
        /// Device code returned by the service
        /// </summary>
        public string DeviceCode => this.Result.DeviceCode;

        /// <summary>
        /// Verification URL where the user must navigate to authenticate using the device code and credentials.
        /// </summary>
        public string VerificationUrl => this.Result.VerificationUrl;

        /// <summary>
        /// Time when the device code will expire.
        /// </summary>
        public DateTimeOffset ExpiresOn => this.Result.ExpiresOn;

        /// <summary>
        /// Polling interval time to check for completion of authentication flow.
        /// </summary>
        public long Interval => this.Result.Interval;

        /// <summary>
        /// User friendly text response that can be used for display purpose.
        /// </summary>
        public string Message => this.Result.Message;

        /// <summary>
        /// Identifier of the client requesting device code.
        /// </summary>
        public string ClientId => this.Result.ClientId;

        /// <summary>
        /// Identifier of the target resource that would be the recipient of the token.
        /// </summary>
        public string Resource => this.Result.Resource;

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