using OneTimePassword.AuthenticatorAccounts;
using OneTimePassword.Authenticators;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword.Authenticators
{
    public sealed class SteamAuthenticator : TimeBasedAuthenticator
    {
        const uint SteamDefaultTimeStep = 30;
        const uint SteamDefaultPasswordLength = 5;
        public OneTimePassword GeneratePassword(SteamAccount account)
        {
            return new OneTimePassword(GeneratePassword(account.PasswordLength, HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()), account.Secret, DateTimeOffset.Now, account.Period), DateTimeOffset.Now + account.Period);
        }
        public override string GeneratePassword(uint length, HMAC hmac, byte[] secret, DateTimeOffset time, TimeSpan timeStep)
        {
            if (length < 6) throw new ArgumentOutOfRangeException(nameof(length), "The generated password cannot be than shorter 6 characters.");
            if (secret.Length < 16) throw new ArgumentOutOfRangeException(nameof(secret), "The secret cannot be shorter than 128 bits.");

            return this.TruncatePassword(GenerateFullCode(hmac, secret, time, timeStep), length);
        }
        /// <summary>
        /// Returns an alphanumerc string, compatible with Steam Guard.
        /// </summary>
        /// <param name="fullCode"></param>
        /// <returns></returns>
        internal new string TruncatePassword(uint fullCode, uint length = SteamDefaultPasswordLength)
        {
            char[] steamAlphanumerics = new char[] { '2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'T', 'V', 'W', 'X', 'Y' };
            string code = fullCode.ToString();
            for (var i = 0; i < length; i++)
            {
                code += steamAlphanumerics[fullCode % steamAlphanumerics.Length];
                fullCode /= (uint) steamAlphanumerics.Length;
            }
            return code;
        }
    }
}