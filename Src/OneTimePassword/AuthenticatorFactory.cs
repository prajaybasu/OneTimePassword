using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OneTimePassword
{
    static class AuthenticatorFactory
    {
        public static Authenticator GetAuthenticator(this OneTimePasswordAccount account)
        {
            if (account.Issuer.Equals("Steam", StringComparison.OrdinalIgnoreCase))
                return new SteamAuthenticator();
            switch(account.Type)
            {
                case AuthenticatorType.HOTP:
                    return new CounterBasedAuthenticator();
                case AuthenticatorType.TOTP:
                    return new TimeBasedAuthenticator();
                default:
                    return new TimeBasedAuthenticator();
            }           
        }
    }
}
