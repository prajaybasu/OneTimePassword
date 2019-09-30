//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using OneTimePassword.AuthenticatorAccounts;
using System;
using System.Security.Cryptography;

namespace OneTimePassword.Authenticators
{
    public class TimeBasedAuthenticator : CounterBasedAuthenticator
    {
        public const uint RFC_DEFAULT_TIMESTEP = 30;

        /// <summary>
        /// Generates an one time password based on RFC 6238 using the given parameters.
        /// </summary>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public OneTimePassword GeneratePassword(AuthenticatorAccount account, DateTimeOffset time)
        {
            if (!(account is TimeBasedAuthenticatorAccount timeAccount)) throw new ArgumentException("Account is not a TOTP account.", nameof(account));
            using (var hmac = HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()))
            {
                return new OneTimePassword(GeneratePassword(hmac, timeAccount.Secret, time, timeAccount.PasswordLength, timeAccount.Period), time + timeAccount.Period);
            }
        }

        /// <summary>
        /// Generates an one time password based on RFC 6238 using the given parameters.
        /// </summary>
        /// <returns></returns>
        public override OneTimePassword GeneratePassword(AuthenticatorAccount account)
        {
            return GeneratePassword(account, DateTimeOffset.Now);
        }

        /// <summary>
        /// Generates an one time password based on RFC 6238 using the given parameters.
        /// </summary>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <param name="time">The time to generate the one time password for.</param>
        /// <param name="length">The length of the password</param>
        /// <param name="timeStep">The period of the one time password in seconds.</param>
        /// <returns cref="string">The generated password</returns>
        public virtual string GeneratePassword(HMAC hmac, byte[] secret, DateTimeOffset time, uint length = RFC_DEFAULT_LENGTH, TimeSpan? timeStep = null)
        {
            return TruncatePassword(GenerateFullCode(hmac, secret, time, timeStep), length);
        }

        /// <summary>
        /// Returns the non truncated code.
        /// </summary>
        /// <param name="hmac">The HMAC to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <param name="time">The time, valid Unix epoch</param>
        /// <returns></returns>
        /// <exception cref="System.ArgumentOutOfRangeException">Thrown when <paramref name="time"/> is not valid Unix time.</exception>
        internal protected static uint GenerateFullCode(HMAC hmac, byte[] secret, DateTimeOffset time, TimeSpan? timeStep = null)
        {
            if (timeStep == null) timeStep = TimeSpan.FromSeconds(RFC_DEFAULT_TIMESTEP);
            if (time.Year < 1970) throw new ArgumentOutOfRangeException(nameof(time), "Time cannot precede Unix Epoch.");
            if (timeStep.Value.TotalSeconds < 1) throw new ArgumentOutOfRangeException(nameof(timeStep), "Time step cannot be less than 1 second.");

            return GenerateFullCode(BitConverter.GetBytes((ulong)(time.ToUnixTimeSeconds() / timeStep.Value.TotalSeconds)), hmac, secret);
        }
    }
}
