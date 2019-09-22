using OneTimePassword.Authenticators;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class CounterBasedAuthenticatorAccount : AuthenticatorAccount
    {
        /// <summary>
        /// The 8 byte counter value
        /// </summary>
        public byte[] Counter { get; set; } = BitConverter.GetBytes(0UL);

        public new Authenticator Authenticator => new CounterBasedAuthenticator();

    }
}
