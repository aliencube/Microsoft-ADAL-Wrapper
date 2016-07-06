using System;

using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Aliencube.AdalWrapper
{
    /// <summary>
    /// This provides interfaces to the <see cref="DeviceCodeResult"/> class.
    /// </summary>
    public interface IDeviceCodeResultWrapper : IDisposable
    {
        /// <summary>
        /// Gets the <see cref="DeviceCodeResult"/> instance.
        /// </summary>
        DeviceCodeResult Result { get; }

        /// <summary>
        /// User code returned by the service
        /// </summary>
        string UserCode { get; }

        /// <summary>
        /// Device code returned by the service
        /// </summary>
        string DeviceCode { get; }

        /// <summary>
        /// Verification URL where the user must navigate to authenticate using the device code and credentials.
        /// </summary>
        string VerificationUrl { get; }

        /// <summary>
        /// Time when the device code will expire.
        /// </summary>
        DateTimeOffset ExpiresOn { get; }

        /// <summary>
        /// Polling interval time to check for completion of authentication flow.
        /// </summary>
        long Interval { get; }

        /// <summary>
        /// User friendly text response that can be used for display purpose.
        /// </summary>
        string Message { get; }

        /// <summary>
        /// Identifier of the client requesting device code.
        /// </summary>
        string ClientId { get; }

        /// <summary>
        /// Identifier of the target resource that would be the recipient of the token.
        /// </summary>
        string Resource { get; }
    }
}