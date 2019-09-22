using OneTimePassword.Authenticators;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class TimeBasedAuthenticatorAccount : AuthenticatorAccount
    {
        /// <summary>
        /// It defines the validity of the OTP issued.
        /// </summary>
        public TimeSpan Period { get; set; } = TimeSpan.FromSeconds(30);

        public new Authenticator Authenticator => new TimeBasedAuthenticator();
    }
}
