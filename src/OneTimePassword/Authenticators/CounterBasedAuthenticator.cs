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

        public OneTimePassword GeneratePassword(CounterBasedAuthenticatorAccount account)
        {
            using (var hmac = HMAC.Create("HMAC" + account.HashAlgorithm.Name.ToUpperInvariant()))
            {
                return new OneTimePassword(GeneratePassword(account.PasswordLength, hmac , account.Secret, account.Counter), account.Counter);
            }
        }


        /// <summary>
        /// Generates an one time password based on RFC 4226 for the provided account.
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        public OneTimePassword GeneratePassword(CounterBasedAuthenticatorAccount account, HMAC hmac)
        {
            return new OneTimePassword(GeneratePassword(account.PasswordLength, hmac, account.Secret, account.Counter));
        }

        /// <summary>
        /// Generates an one time password based on RFC 4226 using the given parameters.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        public virtual string GeneratePassword(uint length, HMAC hmac, byte[] secret, byte[] counter, bool enforceRfcStrict = false)
        {
            if (hmac.HashName != "SHA1" && enforceRfcStrict) throw new ArgumentException("HMAC Algorithm is not valid as per RFC4226.", nameof(hmac));
            return TruncatePassword(GenerateFullCode(counter, hmac, secret), length);
        }

        /// <summary>
        /// Generates the full code as per RFC 4226 specifications.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        
        internal static uint GenerateFullCode(byte[] counter, HMAC hmac, byte[] secret)
        {
            //if (counter < 0) throw new ArgumentOutOfRangeException(nameof(counter), "Counter cannot be less than 0.");
            hmac.Key = secret ?? throw new ArgumentNullException(nameof(secret), "Secret cannot be null.");        
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

        public override OneTimePassword GeneratePassword(AuthenticatorAccount account)
        {
            if(account is CounterBasedAuthenticatorAccount)
            {
                return GeneratePassword(account as CounterBasedAuthenticatorAccount);
            }
            else
            {
                throw new InvalidOperationException("Account not supported by authenticator.");
            }
        }
    }
}
