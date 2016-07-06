using System;

#if NET45
using System.Runtime.Serialization;
#endif

using Microsoft.IdentityModel.Clients.ActiveDirectory;

#if !NET45
using ApplicationException = System.InvalidOperationException;
#endif

namespace Aliencube.AdalWrapper.Exceptions
{
    /// <summary>
    /// This represents the exception entity thrown when the <see cref="AuthenticationContext"/> instance is null.
    /// </summary>
    public class AuthenticationContextNullException : ApplicationException
    {
        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextNullException"/> class.
        /// </summary>
        public AuthenticationContextNullException()
            : this("AuthenticationContext is null")
        {
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextNullException"/> class.
        /// </summary>
        /// <param name="message">A message that describes the error. </param>
        public AuthenticationContextNullException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextNullException"/> class.
        /// </summary>
        /// <param name="message">The error message that explains the reason for the exception. </param>
        /// <param name="innerException">The exception that is the cause of the current exception. If the <paramref name="innerException" /> parameter is not a null reference, the current exception is raised in a catch block that handles the inner exception. </param>
        public AuthenticationContextNullException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

#if NET45
        /// <summary>
        /// Initialises a new instance of the <see cref="AuthenticationContextNullException"/> class.
        /// </summary>
        /// <param name="info">The object that holds the serialized object data. </param>
        /// <param name="context">The contextual information about the source or destination. </param>
        protected AuthenticationContextNullException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
#endif
    }
}