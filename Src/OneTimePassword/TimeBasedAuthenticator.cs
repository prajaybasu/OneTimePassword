//  
// Copyright 2016 Prajay Basu.
// Licensed under the Apache License, Version 2.0.  See LICENSE file in the project root for full license information.  
//
using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace OneTimePassword
{
    public static class TimeBasedAuthenticator
    {
        /// <summary>
        /// Generates an one time password based on RFC 6238 using the given parameters.
        /// </summary>
        /// <param name="length">The length of the password</param>
        /// <param name="hmac">The HMAC algorithm to use.</param>
        /// <param name="secret">The secret in binary encoding.</param>
        /// <param name="time">The time to generate the one time password for.</param>
        /// <param name="period">The period of the one time password in seconds.</param>
        /// <returns></returns>
        public static string GeneratePassword(int length, HMAC hmac, byte[] secret, DateTimeOffset time, TimeSpan period)
        {
            Contract.Requires(time.Year >= 1970, "Time before Epoch has undefined behavior");
            return CounterBasedAuthenticator.GeneratePassword((long) (time.ToUnixTimeSeconds()/period.TotalSeconds), length,hmac,secret);
        }
    }
}
