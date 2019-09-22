//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using OneTimePassword.AuthenticatorAccounts;
using System;
using System.Linq;
using System.Security.Cryptography;

namespace OneTimePassword.Authenticators
{
    public class CounterBasedAuthenticator : Authenticator
    {
        public const uint RFC_DEFAULT_LENGTH = 6;

        public override OneTimePassword GeneratePassword(AuthenticatorAccount account)
        {
            var counterAccount = account as CounterBasedAuthenticatorAccount;
            if (counterAccount == null) throw new ArgumentException("Account is not a HOTP account.", nameof(account));
            using (var hmac = HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()))
            {
                return new OneTimePassword(GeneratePassword( hmac, counterAccount.Secret, counterAccount.Counter, counterAccount.PasswordLength), counterAccount.Counter);
            }
        }

        public OneTimePassword GeneratePassword(CounterBasedAuthenticatorAccount account)
        {
            using (var hmac = HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()))
            {
                return new OneTimePassword(GeneratePassword(hmac , account.Secret, account.Counter, account.PasswordLength), account.Counter);
            }
        }


        /// <summary>
        /// Generates an one time password based on RFC 4226 for the provided account.
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        public OneTimePassword GeneratePassword(CounterBasedAuthenticatorAccount account, HMAC hmac)
        {
            return new OneTimePassword(GeneratePassword(hmac, account.Secret, account.Counter, account.PasswordLength));
        }

        /// <summary>
        /// Generates an one time password based on RFC 4226 using the given parameters.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        public virtual string GeneratePassword(HMAC hmac, byte[] secret, byte[] counter, uint length = RFC_DEFAULT_LENGTH, bool enforceRfc4226Strict = false)
        {
            return TruncatePassword(GenerateFullCode(counter, hmac, secret, enforceRfc4226Strict), length);
        }

        /// <summary>
        /// Generates the full code compliant to the RFC 4226 specification.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        
        internal static uint GenerateFullCode(byte[] counter, HMAC hmac, byte[] secret, bool enforceRfc4226Strict = false)
        {
            if (secret.Length < 16) throw new ArgumentOutOfRangeException(nameof(secret), "The secret cannot be shorter than 128 bits");
            if (hmac.HashName != "SHA1" && enforceRfc4226Strict) throw new ArgumentException("HMAC Algorithm is not compliant with RFC 4226.", nameof(hmac));
            hmac.Key = secret ?? throw new ArgumentNullException(nameof(secret), "The secret cannot be null.");        
            var hash = hmac.ComputeHash(ReverseIfLittleEndian(counter));
            var bytes = new byte[4];
            var offset = hash.Last() & 0xF;
            Array.Copy(hash, offset, bytes, 0, bytes.Length);          
            return BitConverter.ToUInt32(ReverseIfLittleEndian(bytes), 0) & Int32.MaxValue;

            byte[] ReverseIfLittleEndian(byte[] array)
            {
                if (BitConverter.IsLittleEndian) Array.Reverse(array);
                return array;
            }
        }

        internal string TruncatePassword(uint fullCode, uint length = RFC_DEFAULT_LENGTH)
        {
            if (length < 6 || length > 9) throw new ArgumentOutOfRangeException(nameof(length), "The generated password must be between 6 and 9 characters long.");
           
            return (fullCode % Math.Pow(10, length)).ToString().PadLeft((int)length, '0');
        }
    }
}
