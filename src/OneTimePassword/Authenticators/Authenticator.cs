using OneTimePassword.AuthenticatorAccounts;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public abstract class Authenticator
    {
        public abstract OneTimePassword GeneratePassword(AuthenticatorAccount account);

    }
}
