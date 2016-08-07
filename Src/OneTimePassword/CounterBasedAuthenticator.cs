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
    public static class CounterBasedAuthenticator
    {
        //internal static readonly int[] digitPowers = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };
        /// <summary>
        /// Generates an one time password based on RFC 4226 using the given parameters.
        /// </summary>
        /// <param name="counter">The counter value, as per the RFC document.</param>
        /// <param name="length">The length of the password.</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <returns></returns>
        public static string GeneratePassword(long counter,int length,HMAC hmac, byte[] secret)
        {
            Contract.Requires(counter > 0,"Counter cannot be less than zero");
            Contract.Requires(length > 0);
            Contract.Requires(secret != null);
            var text = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                text = text.Reverse().ToArray();
            hmac.Key = secret;
            var hash = hmac.ComputeHash(text);
            int offset = hash.Last() & 0xF;
            return ((   ((hash[offset + 0] & 0x7f) << 24) |
                        ((hash[offset + 1] & 0xff) << 16) |
                        ((hash[offset + 2] & 0xff) << 8)  |
                        (hash[offset + 3] & 0xff)) % Math.Pow(10,length)).ToString().PadLeft(length,'0');
        }
    }
}
