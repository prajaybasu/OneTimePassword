//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;

namespace OneTimePassword
{
    public class CounterBasedAuthenticator : Authenticator
    {
        /// <summary>
        /// Generates an one time password based on RFC 4226 for the provided account.
        /// </summary>
        /// <param name="account"></param>
        /// <returns></returns>
        public override OneTimePassword GeneratePassword(OneTimePasswordAccount account)
        {
            return new OneTimePassword(GeneratePassword(account.Counter, account.PasswordLength, account.Algorithm.GetHmac(), account.Secret).ToString(), DateTime.MaxValue);
        }

        /// <summary>
        /// Generates an one time password based on RFC 4226 using the given parameters.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        public string GeneratePassword(long counter,int length,HMAC hmac, byte[] secret) => TruncatePassword(GenerateFullCode(counter,hmac,secret),length);

        /// <summary>
        /// Generates the full code as per RFC 4226 specifications.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        
        internal static uint GenerateFullCode(long counter, HMAC hmac, byte[] secret)
        {
        
            if (counter < 0) throw new ArgumentOutOfRangeException(nameof(counter), "Counter cannot be less than zero.");
            if (secret == null) throw new ArgumentNullException(nameof(secret), "Secret cannot be null.");
            Contract.EndContractBlock();
            var text = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                text = text.Reverse().ToArray();
            hmac.Key = secret;
            var hash = hmac.ComputeHash(text);
            int offset = hash.Last() & 0xF;
            byte[] bytes = new byte[4];
            Array.Copy(hash, offset, bytes, 0, 4);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0) & 0x7fffffff;
        }
    }
}
