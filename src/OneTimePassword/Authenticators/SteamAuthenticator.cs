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
        private const uint STEAM_DEFAULT_TIMESTEP = 30;
        private const uint STEAM_DEFAULT_LENGTH = 5;

        public new OneTimePassword GeneratePassword(AuthenticatorAccount account, DateTimeOffset time)
        {
            if (!(account is SteamAccount steamAccount)) throw new ArgumentException("Account is not a Steam account.", nameof(account));
            using (var hmac = HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()))
            {
                return new OneTimePassword(GeneratePassword(hmac, steamAccount.Secret, time, steamAccount.PasswordLength, steamAccount.Period));
            }
        }

        public override string GeneratePassword( HMAC hmac, byte[] secret, DateTimeOffset time, uint length = STEAM_DEFAULT_LENGTH, TimeSpan? timeStep = null)
        {
            if (timeStep == null) timeStep = TimeSpan.FromSeconds(STEAM_DEFAULT_TIMESTEP);
            return this.TruncatePassword(GenerateFullCode(hmac, secret, time, timeStep), length);
        }

        /// <summary>
        /// Returns an alphanumerc string compatible with Steam Guard.
        /// </summary>
        /// <param name="fullCode"></param>
        /// <returns></returns>
        internal new string TruncatePassword(uint fullCode, uint length = STEAM_DEFAULT_LENGTH)
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