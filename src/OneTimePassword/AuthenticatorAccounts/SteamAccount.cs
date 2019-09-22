using OneTimePassword.Authenticators;
using System;
using System.Collections.Generic;
using System.Text;

namespace OneTimePassword.AuthenticatorAccounts
{
    public class SteamAccount : TimeBasedAuthenticatorAccount
    {
        public new Authenticator Authenticator => new SteamAuthenticator();
    }
}
