using OneTimePassword.Authenticators;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class SteamAccount : TimeBasedAuthenticatorAccount
    {
        public SteamAccount() : base()
        {
            Issuer = "Steam";
        }

        public new Authenticator Authenticator => new SteamAuthenticator();

        /// <summary>
        /// Generates a one time password using the given parameters.
        /// </summary>
        new public OneTimePassword GeneratePassword() => (Authenticator as SteamAuthenticator).GeneratePassword(this);
    }
}
