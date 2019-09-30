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
    }
}
