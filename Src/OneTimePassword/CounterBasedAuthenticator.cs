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
    public class CounterBasedAuthenticator
    {

        //internal static readonly int[] digitPowers = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
        /// <summary>
        /// Generates an one time password based on RFC 4226 using the given parameters.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        public static string GeneratePassword(long counter,int length,HMAC hmac, byte[] secret) => GenerateFullCode(counter,hmac,secret).ToTruncatedString(length);

        /// <summary>
        /// Returns the non truncated code.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password to be generated.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        internal static uint GenerateFullCode(long counter, HMAC hmac, byte[] secret)
        {
            Contract.Requires<InvalidOperationException>(counter > 0, "Counter cannot be less than zero");
            Contract.Requires<ArgumentNullException>(secret != null, "Secret cannot be null");
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
